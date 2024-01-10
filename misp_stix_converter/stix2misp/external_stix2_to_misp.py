#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import re
from .exceptions import (
    InvalidSTIXPatternError, UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError,
    UnknownPatternTypeError, UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import _INDICATOR_TYPING
from .converters import (
    ExternalSTIX2AttackPatternConverter, ExternalSTIX2CampaignConverter,
    ExternalSTIX2CourseOfActionConverter, ExternalSTIX2IdentityConverter,
    ExternalSTIX2IndicatorConverter, ExternalSTIX2IntrusionSetConverter,
    ExternalSTIX2LocationConverter, ExternalSTIX2MalwareAnalysisConverter,
    ExternalSTIX2MalwareConverter, ExternalSTIX2ThreatActorConverter,
    ExternalSTIX2ToolConverter, ExternalSTIX2VulnerabilityConverter,
    STIX2ObservableObjectConverter)
from .stix2_to_misp import (
    STIX2toMISPParser, _COURSE_OF_ACTION_TYPING, _GALAXY_OBJECTS_TYPING,
    _IDENTITY_TYPING, _NETWORK_TRAFFIC_TYPING, _OBSERVABLE_TYPING,
    _OBSERVED_DATA_TYPING, _SDO_TYPING, _VULNERABILITY_TYPING)
from collections import defaultdict
from pymisp import MISPGalaxy, MISPGalaxyCluster, MISPObject
from stix2.v20.observables import (
    AutonomousSystem as AutonomousSystem_v20, Directory as Directory_v20,
    DomainName as DomainName_v20, EmailAddress as EmailAddress_v20,
    EmailMessage as EmailMessage_v20, File as File_v20,
    IPv4Address as IPv4Address_v20, IPv6Address as IPv6Address_v20,
    MACAddress as MACAddress_v20, Mutex as Mutex_v20,
    NetworkTraffic as NetworkTraffic_v20, Process as Process_v20,
    URL as URL_v20, WindowsPEBinaryExt as WindowsPEBinaryExt_v20,
    WindowsRegistryKey as WindowsRegistryKey_v20,
    X509Certificate as X509Certificate_v20)
from stix2.v20.sdo import (
    CourseOfAction as CourseOfAction_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.observables import (
    AutonomousSystem as AutonomousSystem_v21, Directory as Directory_v21,
    DomainName as DomainName_v21, EmailAddress as EmailAddress_v21,
    EmailMessage as EmailMessage_v21, File as File_v21,
    IPv4Address as IPv4Address_v21, IPv6Address as IPv6Address_v21,
    MACAddress as MACAddress_v21, Mutex as Mutex_v21,
    NetworkTraffic as NetworkTraffic_v21, Process as Process_v21,
    URL as URL_v21, WindowsPEBinaryExt as WindowsPEBinaryExt_v21,
    WindowsRegistryKey as WindowsRegistryKey_v21,
    X509Certificate as X509Certificate_v21)
from stix2.v21.sdo import (
    CourseOfAction as CourseOfAction_v21, Indicator as Indicator_v21, Location,
    ObservedData as ObservedData_v21, Vulnerability as Vulnerability_v21)
from typing import Optional, Tuple, Union

# Useful lists
_observable_skip_properties = (
    'content_ref', 'content_type', 'decryption_key', 'defanged',
    'encryption_algorithm', 'extensions', 'id', 'is_encrypted', 'is_multipart',
    'magic_number_hex', 'received_lines', 'sender_ref', 'spec_version', 'type'
)

# Typing definitions
_AUTONOMOUS_SYSTEM_TYPING = Union[
    AutonomousSystem_v20, AutonomousSystem_v21
]
_DIRECTORY_TYPING = Union[
    Directory_v20, Directory_v21
]
_DOMAIN_NAME_TYPING = Union[
    DomainName_v20, DomainName_v21
]
_EMAIL_ADDRESS_TYPING = Union[
    EmailAddress_v20, EmailAddress_v21
]
_EMAIL_MESSAGE_TYPING = Union[
    EmailMessage_v20, EmailMessage_v21
]
_FILE_TYPING = Union[
    File_v20, File_v21
]
_GENERIC_SDO_TYPING = Union[
    CourseOfAction_v20,
    CourseOfAction_v21,
    Vulnerability_v20,
    Vulnerability_v21
]
_OBSERVABLE_OBJECTS_TYPING = Union[
    Directory_v20, Directory_v21,
    DomainName_v20, DomainName_v21,
    EmailAddress_v20, EmailAddress_v21,
    EmailMessage_v20, EmailMessage_v21,
    File_v20, File_v21,
    IPv4Address_v20, IPv4Address_v21,
    IPv6Address_v20, IPv6Address_v21,
    MACAddress_v20, MACAddress_v21,
    Mutex_v20, Mutex_v21,
    NetworkTraffic_v20, NetworkTraffic_v21,
    Process_v20, Process_v21,
    URL_v20, URL_v21,
    WindowsPEBinaryExt_v20, WindowsPEBinaryExt_v21,
    WindowsRegistryKey_v20, WindowsRegistryKey_v21,
    X509Certificate_v20, X509Certificate_v21
]
_IP_ADDRESS_TYPING = Union[
    IPv4Address_v20, IPv4Address_v21,
    IPv6Address_v20, IPv6Address_v21
]
_MAC_ADDRESS_TYPING = Union[
    MACAddress_v20, MACAddress_v21
]
_MUTEX_TYPING = Union[
    Mutex_v20, Mutex_v21
]
_PE_EXTENSION_TYPING = Union[
    WindowsPEBinaryExt_v20, WindowsPEBinaryExt_v21
]
_PROCESS_TYPING = Union[
    Process_v20, Process_v21
]
_REGISTRY_KEY_TYPING = Union[
    WindowsRegistryKey_v20, WindowsRegistryKey_v21
]
_URL_TYPING = Union[
    URL_v20, URL_v21
]
_X509_TYPING = Union[
    X509Certificate_v20, X509Certificate_v21
]


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, distribution: Optional[int] = 0,
                 sharing_group_id: Optional[int] = None,
                 galaxies_as_tags: Optional[bool] = False,
                 cluster_distribution: Optional[int] = 0,
                 cluster_sharing_group_id: Optional[int] = None):
        super().__init__(distribution, sharing_group_id, galaxies_as_tags)
        self._set_cluster_distribution(
            self._sanitise_distribution(cluster_distribution),
            self._sanitise_sharing_group_id(cluster_sharing_group_id)
        )
        self._mapping = ExternalSTIX2toMISPMapping
        # parsers
        self._attack_pattern_parser: ExternalSTIX2AttackPatternConverter
        self._campaign_parser: ExternalSTIX2CampaignConverter
        self._course_of_action_parser: ExternalSTIX2CourseOfActionConverter
        self._identity_parser: ExternalSTIX2IdentityConverter
        self._indicator_parser: ExternalSTIX2IndicatorConverter
        self._intrusion_set_parser: ExternalSTIX2IntrusionSetConverter
        self._location_parser: ExternalSTIX2LocationConverter
        self._malware_analysis_parser: ExternalSTIX2MalwareAnalysisConverter
        self._malware_parser: ExternalSTIX2MalwareConverter
        self._observable_object_parser: STIX2ObservableObjectConverter
        self._threat_actor_parser: ExternalSTIX2ThreatActorConverter
        self._tool_parser: ExternalSTIX2ToolConverter
        self._vulnerability_parser: ExternalSTIX2VulnerabilityConverter

    @property
    def cluster_distribution(self) -> dict:
        return self.__cluster_distribution

    @property
    def observable_object_parser(self) -> STIX2ObservableObjectConverter:
        if not hasattr(self, '_observable_object_parser'):
            self._set_observable_object_parser()
        return self._observable_object_parser

    def _set_attack_pattern_parser(self) -> ExternalSTIX2AttackPatternConverter:
        self._attack_pattern_parser = ExternalSTIX2AttackPatternConverter(self)

    def _set_campaign_parser(self) -> ExternalSTIX2CampaignConverter:
        self._campaign_parser = ExternalSTIX2CampaignConverter(self)

    def _set_cluster_distribution(
            self, distribution: int, sharing_group_id: Union[int, None]):
        cluster_distribution = {'distribution': distribution}
        if distribution == 4 and sharing_group_id is not None:
            cluster_distribution['sharing_group_id'] = sharing_group_id
        self.__cluster_distribution = cluster_distribution

    def _set_course_of_action_parser(self) -> ExternalSTIX2CourseOfActionConverter:
        self._course_of_action_parser = ExternalSTIX2CourseOfActionConverter(self)

    def _set_identity_parser(self) -> ExternalSTIX2IdentityConverter:
        self._identity_parser = ExternalSTIX2IdentityConverter(self)

    def _set_indicator_parser(self) -> ExternalSTIX2IndicatorConverter:
        self._indicator_parser = ExternalSTIX2IndicatorConverter(self)

    def _set_intrusion_set_parser(self) -> ExternalSTIX2IntrusionSetConverter:
        self._intrusion_set_parser = ExternalSTIX2IntrusionSetConverter(self)

    def _set_location_parser(self) -> ExternalSTIX2LocationConverter:
        self._location_parser = ExternalSTIX2LocationConverter(self)

    def _set_malware_analysis_parser(self) -> ExternalSTIX2MalwareAnalysisConverter:
        self._malware_analysis_parser = ExternalSTIX2MalwareAnalysisConverter(self)

    def _set_malware_parser(self) -> ExternalSTIX2MalwareConverter:
        self._malware_parser = ExternalSTIX2MalwareConverter(self)

    def _set_observable_object_parser(self) -> STIX2ObservableObjectConverter:
        self._observable_object_parser = STIX2ObservableObjectConverter(self)

    def _set_threat_actor_parser(self) -> ExternalSTIX2ThreatActorConverter:
        self._threat_actor_parser = ExternalSTIX2ThreatActorConverter(self)

    def _set_tool_parser(self) -> ExternalSTIX2ToolConverter:
        self._tool_parser = ExternalSTIX2ToolConverter(self)

    def _set_vulnerability_parser(self) -> ExternalSTIX2VulnerabilityConverter:
        self._vulnerability_parser = ExternalSTIX2VulnerabilityConverter(self)

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._check_uuid(observable.id)
        to_load = {'used': {}, 'observable': observable}
        try:
            self._observable[observable.id] = to_load
        except AttributeError:
            self._observable = {observable.id: to_load}

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    @staticmethod
    def _fetch_identity_object_name(identity: _IDENTITY_TYPING) -> str:
        if getattr(identity, 'identity_class', None) == 'organization':
            return 'organization'
        return 'identity'

    def _get_attributes_from_generic_SDO(
            self, stix_object: _GENERIC_SDO_TYPING, mapping: str):
        for feature, attribute in getattr(self._mapping, mapping)().items():
            if hasattr(stix_object, feature):
                yield {'value': getattr(stix_object, feature), **attribute}

    def _handle_import_case(self, stix_object: _SDO_TYPING, attributes: list,
                            name: str, *force_object: Tuple[str]):
        """
        After we extracted attributes from a STIX object (Indicator pattern,
        Observable object, Vulnerability fields, etc.), we want to know if it is
        appropriate to import one single attribute or to create a MISP object with
        an association of attributes included in a given object template.

        :param stix_object: The STIX object we convert into a MISP data structure
        :param attributes: The attribute(s) extracted from the STIX object
        :param name: The MISP object name or MISP attribute type to be used for the
            converted MISP feature
        :param force_object: List of object_relation values that force the MISP
            object creation over a MISP attribute, if at least one of the attribute
            has a matching object_relation field
        """
        if self._handle_object_forcing(attributes, force_object):
            self._handle_object_case(stix_object, attributes, name)
        else:
            self._add_misp_attribute(
                dict(
                    self._create_attribute_dict(stix_object), **attributes[0]
                ),
                stix_object
            )

    def _handle_object_case(
            self, stix_object: _SDO_TYPING, attributes: list, name: str):
        """
        The attributes we generated from data converted from STIX are considered
        as part of an object template.

        :param stix_object: The STIX object we convert to a MISP object
        :param attributes: The attributes extracted from the STIX object
        :param name: The MISP object name
        """
        misp_object = self._create_misp_object(name, stix_object)
        tags = tuple(self._handle_tags_from_stix_fields(stix_object))
        if tags:
            for attribute in attributes:
                misp_attribute = misp_object.add_attribute(**attribute)
                for tag in tags:
                    misp_attribute.add_tag(tag)
            return self.misp_event.add_object(misp_object)
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return self.misp_event.add_object(misp_object)

    @staticmethod
    def _handle_object_forcing(attributes: list, force_object: tuple) -> bool:
        if len(attributes) > 1:
            return True
        return attributes[0]['object_relation'] in force_object

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.object_type_refs_to_skip():
                continue
            if object_type in self._mapping.observable_object_types():
                if self._observable.get(object_ref) is not None:
                    observable = self._observable[object_ref]
                    if self.misp_event.uuid not in observable['used']:
                        observable['used'][self.misp_event.uuid] = False
                continue
            try:
                self._handle_object(object_type, object_ref)
            except UnknownStixObjectTypeError as error:
                self._unknown_stix_object_type_error(error)
            except UnknownParsingFunctionError as error:
                self._unknown_parsing_function_error(error)

    def _handle_observables_mapping(self, observable_mapping: set) -> str:
        """
        Simple Observable object types handling function.
        We check if the Observable object types are actually mapped with a
        parsing function and return it, or raise an exception.

        :param observable_mapping: The observable types in a set
        :returns: The feature used to identify the appropriate parsing function
        :raises: Exception when the observable types are not known
        """
        to_call = '_'.join(sorted(observable_mapping))
        mapping = self._mapping.observable_mapping(to_call)
        if mapping is None:
            raise UnknownObservableMappingError(to_call)
        return mapping

    def _handle_pattern_mapping(self, indicator: _INDICATOR_TYPING) -> str:
        """
        Mapping between an indicator pattern and the function used to parse it and
        convert it into a MISP attribute or object.

        :param indicator: The indicator
        :return: The parsing function name to convert the indicator into a MISP
            attribute or object, using its pattern
        """
        if isinstance(indicator, Indicator_v21) and indicator.pattern_type != 'stix':
            try:
                return f'_parse_{indicator.pattern_type}_pattern'
            except KeyError:
                raise UnknownPatternTypeError(indicator.pattern_type)
        if self._is_pattern_too_complex(indicator.pattern):
            return '_create_stix_pattern_object'
        return '_parse_stix_pattern'

    def _handle_unparsed_content(self):
        if not hasattr(self, '_observable'):
            return super()._handle_unparsed_content()
        unparsed_content = defaultdict(list)
        for object_id, content in self._observable.items():
            if content['used'][self.misp_event.uuid]:
                continue
            unparsed_content[content['observable'].type].append(object_id)
        for observable_type in self._mapping.observable_object_types():
            if observable_type not in unparsed_content:
                continue
            feature = self._mapping.observable_mapping(observable_type)
            if feature is None:
                self._observable_object_mapping_error(
                    unparsed_content[observable_type][0]
                )
                continue
            to_call = f'_parse_{feature}_observable_object'
            for object_id in unparsed_content[observable_type]:
                if self._observable[object_id]['used'][self.misp_event.uuid]:
                    continue
                try:
                    getattr(self.observable_object_parser, to_call)(object_id)
                except Exception as exception:
                    self._observable_object_error(object_id, exception)
        super()._handle_unparsed_content()

    def _parse_loaded_features(self):
        if hasattr(self, '_observable'):
            for observable in self._observable.values():
                observable['used'][self.misp_event.uuid] = False
        super()._parse_loaded_features()

    def _parse_observable_objects(self, observed_data: _OBSERVED_DATA_TYPING):
        """
        Observed Data with embedded `objects` field parsing.
        Depending on the Observable object types, we call the appropriate
        parsing function.

        :param observed_data: The Observed Data object
        """
        observable_types = set(
            observable['type'] for observable in observed_data.objects.values()
        )
        mapping = self._handle_observables_mapping(observable_types)
        feature = f'_parse_{mapping}_observable_objects'
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        parser(observed_data, 'objects')

    def _parse_observable_refs(self, observed_data: ObservedData_v21):
        """
        Observed Data with `object_refs` field parsing.
        The observable types are extracted first. Depending on the types, we
        look for the referenced Observable objects and parse them.

        :param observed_data: The Observed Data object
        """
        observable_types = set(
            reference.split('--')[0] for reference in observed_data.object_refs
        )
        mapping = self._handle_observables_mapping(observable_types)
        feature = f'_parse_{mapping}_observable_objects'
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        parser(observed_data, 'object_refs')

    def _parse_observed_data(self, observed_data_ref: str):
        """
        Observed Data parsing function.
        We want first to find out which parsing function is the best depending
        whether there is an `object_refs` field or the embedded `objects`.
        Then we call the appropriate parsing function

        :param observed_data: The Observed Data object
        """
        observed_data = self._get_stix_object(observed_data_ref)
        try:
            if hasattr(observed_data, 'object_refs'):
                self._parse_observable_refs(observed_data)
            else:
                self._parse_observable_objects(observed_data)
        except UnknownObservableMappingError as observable_types:
            self._observable_mapping_error(observed_data.id, observable_types)

    ################################################################################
    #                     OBSERVABLE OBJECTS PARSING FUNCTIONS                     #
    ################################################################################

    def _check_email_observable_fields(
            self, email_message: _EMAIL_MESSAGE_TYPING) -> bool:
        fields = tuple(self._get_populated_properties(email_message))
        if len(fields) > 1:
            return True
        length = 0
        for field, values in getattr(
            email_message, 'additional_header_fields', {}
        ).items():
            if field in self._mapping.email_additional_header_fields_mapping():
                length += len(values) if isinstance(values, list) else 1
        return length > 1

    def _check_file_observable_fields(self, file_object: _FILE_TYPING) -> bool:
        if 'windows-pebinary-ext' in getattr(file_object, 'extensions', {}):
            return True
        fields = [
            field for field in self._mapping.file_object_mapping()
            if hasattr(file_object, field)
        ]
        if len(fields) > 1:
            return True
        return len(getattr(file_object, 'hashes', {})) > 1

    def _check_registry_key_observable_fields(
            self, registry_key: _REGISTRY_KEY_TYPING) -> bool:
        if 'values' in registry_key.properties_populated():
            if len(registry_key['values']) > 1:
                return True
            value = registry_key['values'][0]
            return 'name' in value or 'data_type' in value
        return False

    def _create_attribute_from_observable_object(
            self, attribute_type: str, value: str,
            observed_data_id: str, object_id: str) -> dict:
        return {
            'type': attribute_type,
            'value': value,
            'uuid': self._create_v5_uuid(
                f'{observed_data_id} - {object_id} - {attribute_type} - {value}'
            ),
            'comment': f'Original Observed Data ID: {observed_data_id}'
        }

    def _create_attribute_from_observable_object_with_id(
            self, attribute_type: str, value: str,
            observable_object_id: str, observed_data_id: str) -> dict:
        return {
            'type': attribute_type,
            'value': value,
            'uuid': self._sanitise_uuid(observable_object_id),
            'comment': f'Original Observed Data ID: {observed_data_id}'
        }

    def _create_attribute_from_single_observable_object(
            self, attribute_type: str, value: str, observed_data_id: str) -> dict:
        return {
            'type': attribute_type,
            'value': value,
            'uuid': self._create_v5_uuid(
                f'{observed_data_id} - {attribute_type} - {value}'
            ),
            'comment': f'Original Observed Data ID: {observed_data_id}'
        }

    def _fetch_observable_object_refs(
            self, observed_data: _OBSERVED_DATA_TYPING):
        for reference in observed_data.object_refs:
            self._observable[reference]['used'][self.misp_event.uuid] = True
            yield self._observable[reference]['observable']

    def _fetch_observable_object_refs_with_id(
            self, observed_data: _OBSERVED_DATA_TYPING):
        for reference in observed_data.object_refs:
            self._observable[reference]['used'][self.misp_event.uuid] = True
            yield reference, self._observable[reference]['observable']

    @staticmethod
    def _fetch_observable_objects(
            observed_data: _OBSERVED_DATA_TYPING):
        for observable_object in observed_data.objects.values():
            yield observable_object

    @staticmethod
    def _fetch_observable_objects_with_id(
            observed_data: _OBSERVED_DATA_TYPING):
        yield from observed_data.objects.items()

    def _fill_observable_object_attribute(
            self, reference: str, observed_data_id: str) -> dict:
        return {
            'uuid': self._create_v5_uuid(reference),
            'comment': f'Original Observed Data ID: {observed_data_id}'
        }

    @staticmethod
    def _filter_observable_objects(
            observable_objects: dict, *object_types: Tuple[str]):
        for object_id, observable_object in observable_objects.items():
            if observable_object.type in object_types:
                yield object_id

    def _force_observable_as_object(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING,
            object_type: str) -> bool:
        fields = getattr(self._mapping, f'{object_type}_object_fields')()
        if any(hasattr(observable_object, field) for field in fields):
            return True
        return getattr(self, f'_check_{object_type}_observable_fields')(
            observable_object
        )

    def _handle_observable_object_attribute(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING, object_id: str,
            observed_data_id: str, references: str) -> dict:
        if hasattr(observable_object, 'id'):
            return self._fill_observable_object_attribute(
                f'{observable_object.id} - {references}', observed_data_id
            )
        return self._fill_observable_object_attribute(
            f'{observed_data_id} - {object_id} - {references}',
            observed_data_id
        )

    def _handle_observable_attribute(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING, feature: str,
            attribute_type: str, observed_data_id: str, object_id: str) -> dict:
        value = getattr(observable_object, feature)
        if hasattr(observable_object, 'id'):
            return self._create_attribute_from_observable_object_with_id(
                attribute_type, value, observable_object.id, observed_data_id
            )
        return self._create_attribute_from_observable_object(
            attribute_type, value, observed_data_id, object_id
        )

    def _handle_observable_special_attribute(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING, value: str,
            attribute_type: str, observed_data_id: str, object_id: str) -> dict:
        if hasattr(observable_object, 'id'):
            return self._create_attribute_from_observable_object_with_id(
                attribute_type, value, observable_object.id, observed_data_id
            )
        return self._create_attribute_from_observable_object(
            attribute_type, value, observed_data_id, object_id
        )

    def _handle_single_observable_attribute(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING, feature: str,
            attribute_type: str, observed_data_id: str) -> dict:
        value = getattr(observable_object, feature)
        if hasattr(observable_object, 'id'):
            return self._create_attribute_from_observable_object_with_id(
                attribute_type, value, observable_object.id, observed_data_id
            )
        return self._create_attribute_from_single_observable_object(
            attribute_type, value, observed_data_id
        )

    def _handle_single_observable_special_attribute(
            self, observable_object: _OBSERVABLE_OBJECTS_TYPING, value: str,
            attribute_type: str, observed_data_id: str) -> dict:
        if hasattr(observable_object, 'id'):
            return self._create_attribute_from_observable_object_with_id(
                attribute_type, value, observable_object.id, observed_data_id
            )
        return self._create_attribute_from_single_observable_object(
            attribute_type, value, observed_data_id
        )

    def _has_observable_types(
            self, observable_objects: dict, *object_types: Tuple[str]) -> bool:
        object_ids = self._filter_observable_objects(
            observable_objects, *object_types
        )
        return next(object_ids, None) is not None

    def _parse_as_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_as_observables(observed_data, asset)
        else:
            self._parse_as_single_observable(observed_data, asset)

    def _parse_as_observables(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        autonomous_systems = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, autonomous_system in autonomous_systems.items():
            self._parse_autonomous_system_observables(
                autonomous_system, observed_data, object_id
            )

    def _parse_as_single_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        autonomous_system = next(
            getattr(self, f'_fetch_observable_{asset}')(observed_data)
        )
        self._parse_autonomous_system_single_observable(
            autonomous_system, observed_data
        )

    def _parse_asn_object_attributes(
            self, autonomous_system: _AUTONOMOUS_SYSTEM_TYPING, object_id: str,
            observed_data_id: str, misp_object: MISPObject) -> MISPObject:
        asn_attribute = ('asn', f'AS{autonomous_system.number}')
        misp_object.add_attribute(
            *asn_attribute,
            **self._handle_observable_object_attribute(
                autonomous_system, object_id, observed_data_id,
                ' - '.join(asn_attribute)
            )
        )
        if hasattr(autonomous_system, 'name'):
            description_attribute = ('description', autonomous_system.name)
            misp_object.add_attribute(
                *description_attribute,
                **self._handle_observable_object_attribute(
                    autonomous_system, object_id, observed_data_id,
                    ' - '.join(description_attribute)
                )
            )

    def _parse_asn_observable_object(
            self, autonomous_system: _AUTONOMOUS_SYSTEM_TYPING,
            object_id: str, observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object_from_observable(
            'asn', autonomous_system, object_id, observed_data
        )
        self._parse_asn_object_attributes(
            autonomous_system, object_id.split(' - ')[0],
            observed_data.id, misp_object
        )
        return misp_object

    def _parse_asn_observable_objects(
            self, observed_data: ObservedData_v21, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        if self._has_observable_types(
                observable_objects, 'ipv4-addr', 'ipv6-addr'):
            self._parse_asn_observables(observable_objects, observed_data)
        else:
            self._parse_autonomous_system_observable_objects(
                observable_objects, observed_data
            )

    def _parse_asn_observables(
            self, observable_objects: dict, observed_data: _OBSERVED_DATA_TYPING):
        as_ids = tuple(
            self._filter_observable_objects(
                observable_objects, 'autonomous-system'
            )
        )
        feature = 'observable' if len(as_ids) > 1 else 'single_observable'
        for as_id in as_ids:
            autonomous_system = observable_objects[as_id]
            references = tuple(
                ref for ref, observable_object in observable_objects.items()
                if observable_object.type in ('ipv4-addr', 'ipv6-addr')
                and as_id in getattr(observable_object, 'belongs_to_refs', [])
            )
            if references:
                reference = f"{as_id} - {' - '.join(sorted(references))}"
                misp_object = self._parse_asn_observable_object(
                    autonomous_system, reference, observed_data
                )
                for ip_id in references:
                    ip_address = observable_objects[ip_id]
                    misp_object.add_attribute(
                        'subnet-announced', ip_address.value,
                        **self._handle_observable_object_attribute(
                            ip_address, ip_id, observed_data.id,
                            f'subnet-announced - {ip_address.value}'
                        )
                    )
                self._add_misp_object(misp_object, observed_data)
                continue
            getattr(self, f'_parse_autonomous_system_{feature}_object')(
                autonomous_system, observed_data, as_id
            )

    def _parse_autonomous_system_observable_objects(
            self, autonomous_systems: dict, observed_data: _OBSERVED_DATA_TYPING):
        if len(autonomous_systems) > 1:
            for object_id, autonomous_system in autonomous_systems.items():
                self._parse_autonomous_system_observables(
                    autonomous_system, observed_data, object_id
                )
        else:
            self._parse_autonomous_system_single_observable(
                autonomous_systems.values()[0], observed_data
            )

    def _parse_autonomous_system_observables(
            self, autonomous_system: _OBSERVABLE_OBJECTS_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, object_id: str):
        if hasattr(autonomous_system, 'name'):
            self._add_misp_object(
                self._parse_asn_observable_object(
                    autonomous_system, object_id, observed_data
                ),
                observed_data
            )
        else:
            self._add_misp_attribute(
                self._handle_observable_special_attribute(
                    autonomous_system, f'AS{autonomous_system.number}',
                    'AS', observed_data.id, object_id
                ),
                observed_data
            )

    def _parse_autonomous_system_single_observable(
            self, autonomous_system: _OBSERVABLE_OBJECTS_TYPING,
            observed_data: _OBSERVED_DATA_TYPING,
            object_id: Optional[str] = '0'):
        if hasattr(autonomous_system, 'name'):
            self._add_misp_object(
                self._parse_asn_observable_object(
                    autonomous_system, object_id, observed_data
                ),
                observed_data
            )
        else:
            self._add_misp_attribute(
                self._handle_single_observable_special_attribute(
                    autonomous_system, f'AS{autonomous_system.number}',
                    'AS', observed_data.id
                ),
                observed_data
            )

    def _parse_directory_observable_object(
            self, directory: _DIRECTORY_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        reference = getattr(
            directory, 'id', f'{observed_data.id} - {object_id}'
        )
        misp_object = self._create_misp_object_from_observable(
            'directory', directory, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'directory_object_mapping', directory, misp_object,
            reference, observed_data.id
        )
        return self._add_misp_object(misp_object, observed_data)

    def _parse_directory_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        directories = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, directory in directories.items():
            self._parse_directory_observable_object(
                directory, object_id, observed_data
            )

    def _parse_directory_observables(
            self, object_id: str, observable_objects: dict, mapping: dict,
            feature: str, observed_data: _OBSERVED_DATA_TYPING) -> str:
        directory = observable_objects[object_id]
        misp_object = self._parse_directory_observable_object(
            directory, object_id, observed_data
        )
        if hasattr(directory, 'contains_refs'):
            for contains_ref in directory.contains_refs:
                if contains_ref in mapping:
                    misp_object.add_reference(mapping[contains_ref], 'contains')
                    continue
                if contains_ref in observable_objects:
                    object_type = observable_objects[contains_ref].type
                    contains_uuid = getattr(
                        self, f'_parse_{object_type}_observables'
                    )(
                        contains_ref, observable_objects, mapping,
                        feature, observed_data
                    )
                    mapping[contains_ref] = contains_uuid
                    misp_object.add_reference(contains_uuid, 'contains')
        return misp_object.uuid

    def _parse_domain_ip_observables(
            self, object_id: str, observable_objects: dict, mapping: dict,
            feature: str, observed_data: _OBSERVED_DATA_TYPING) -> str:
        domain = observable_objects.pop(object_id)
        if hasattr(domain, 'resolves_to_refs'):
            domain_reference = getattr(
                domain, 'id', f'{observed_data.id} - {object_id}'
            )
            domain_ip_object = self._create_misp_object_from_observable(
                'domain-ip', domain, object_id, observed_data
            )
            domain_ip_object.add_attribute(
                'domain', domain.value,
                **self._fill_observable_object_attribute(
                    f'{domain_reference} - domain - {domain.value}',
                    observed_data.id
                )
            )
            references = {
                ref: observable_objects[ref] for ref in domain.resolve_to_refs
            }
            for ip_id in self._filter_observable_objects(
                    references, 'ipv4-addr', 'ipv6-addr'):
                ip_address = references[ip_id]
                ip_ref = getattr(ip_address, 'id', ip_id)
                attribute = domain_ip_object.add_attribute(
                    'ip', ip_address.value,
                    f'{domain_reference} - {ip_ref} - ip - {ip_address.value}',
                    observed_data.id
                )
                mapping[ip_id] = attribute.uuid
            misp_object = self._add_misp_object(domain_ip_object, observed_data)
            if any(ref.type == 'domain-name' for ref in references.values()):
                for domain_id in self._filter_observable_objects(
                        references, 'domain-name'):
                    if domain_id in mapping:
                        misp_object.add_reference(
                            mapping[domain_id], 'resolves-to'
                        )
                        continue
                    domain_uuid = self._parse_domain_ip_observables(
                        domain_id, observable_objects, mapping,
                        feature, observed_data
                    )
                    mapping[domain_id] = domain_uuid
                    misp_object.add_reference(domain_uuid, 'resolves-to')
            return misp_object.uuid
        attribute = self._add_misp_attribute(
            getattr(self, f'_handle_{feature}_attribute')(
                domain, 'value', 'domain', observed_data.id, object_id
            ),
            observed_data
        )
        return attribute.uuid

    def _parse_domain_ip_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        domain_ids = tuple(
            self._filter_observable_objects(observable_objects, 'domain-name')
        )
        feature = 'observable' if len(observable_objects) > 1 else 'single_observable'
        mapping = {}
        for domain_id in domain_ids:
            if domain_id not in mapping:
                self._parse_domain_ip_observables(
                    domain_id, observable_objects, mapping,
                    feature, observed_data
                )
        ip_ids = self._filter_observable_objects(
            observable_objects, 'ipv4-addr', 'ipv6-addr'
        )
        for ip_id in ip_ids:
            if ip_id not in mapping:
                self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_attribute')(
                        observable_objects[ip_id], 'value', 'ip-dst',
                        observed_data.id, ip_id
                    ),
                    observed_data
                )

    def _parse_domain_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_generic_observables(
                observed_data, 'value', 'domain', asset
            )
        else:
            self._parse_generic_single_observable(
                observed_data, 'value', 'domain', asset
            )

    def _parse_email_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset):
        if len(observed_data.objects) > 1:
            self._parse_email_address_observables(observed_data, asset)
        else:
            self._parse_email_address_single_observable(observed_data, asset)

    def _parse_email_address_observables(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        email_addresses = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, email_address in email_addresses.items():
            if hasattr(email_address, 'display_name'):
                self._add_misp_attribute(
                    self._create_attribute_from_observable_object(
                        'email-dst', email_address.value,
                        observed_data.id, object_id
                    ),
                    observed_data
                )
                self._add_misp_attribute(
                    self._create_attribute_from_observable_object(
                        'email-dst-display-name', email_address.display_name,
                        observed_data.id, object_id
                    ),
                    observed_data
                )
                continue
            self._add_misp_attribute(
                self._handle_observable_attribute(
                    email_address, 'value', 'email-dst',
                    observed_data.id, object_id
                ),
                observed_data
            )

    def _parse_email_address_single_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        email_address = next(
            getattr(self, f'_fetch_observable_{asset}')(observed_data)
        )
        if hasattr(email_address, 'display_name'):
            self._add_misp_attribute(
                self._create_attribute_from_single_observable_object(
                    'email-dst', email_address.value, observed_data.id
                ),
                observed_data
            )
            self._add_misp_attribute(
                self._create_attribute_from_single_observable_object(
                    'email-dst-display-name', email_address.display_name,
                    observed_data.id
                ),
                observed_data
            )
        else:
            self._add_misp_attribute(
                self._handle_single_observable_attribute(
                    email_address, 'value', 'email-dst', observed_data.id
                ),
                observed_data
            )

    def _parse_email_observable_object(
            self, email_message: _EMAIL_MESSAGE_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING, observable_objects: dict):
        reference = getattr(
            email_message, 'id', f'{observed_data.id} - {object_id}'
        )
        misp_object = self._create_misp_object_from_observable(
            'email', email_message, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'email_object_mapping', email_message, misp_object,
            reference, observed_data.id
        )
        if getattr(email_message, 'from_ref', None) in observable_objects:
            self._parse_email_observable_object_reference(
                misp_object, observable_objects[email_message.from_ref], 'from',
                email_message.from_ref, observed_data.id
            )
        for feature in ('to', 'cc', 'bcc'):
            if getattr(email_message, f'{feature}_refs', None) in observable_objects:
                for address_ref in getattr(email_message, f'{feature}_refs'):
                    self._parse_email_observable_object_reference(
                        misp_object, observable_objects[address_ref], feature,
                        address_ref, observed_data.id
                    )
        if hasattr(email_message, 'additional_header_fields'):
            for field, mapping in self._mapping.email_additional_header_fields_mapping().items():
                if field not in email_message.additional_header_fields:
                    continue
                relation = mapping['object_relation']
                values = email_message.additional_header_fields[field]
                if isinstance(values, list):
                    for index, value in enumerate(values):
                        misp_object.add_attribute(
                            **{
                                'value': value, **mapping,
                                **self._fill_observable_object_attribute(
                                    f'{reference} - {index} - {relation}'
                                    f' - {value}', observed_data.id
                                )
                            }
                        )
                else:
                    misp_object.add_attribute(
                        **{
                            'value': values, **mapping,
                            **self._fill_observable_object_attribute(
                                f'{reference} - {relation} - {values}',
                                observed_data.id
                            )
                        }
                    )
        self._add_misp_object(misp_object, observed_data)

    def _parse_email_observable_object_reference(
            self, misp_object: MISPObject, address: _EMAIL_ADDRESS_TYPING,
            relation: str, object_id: str, observed_data_id: str):
        reference = getattr(
            address, 'id', f'{observed_data_id} - {object_id}'
        )
        misp_object.add_attribute(
            relation, address.value,
            **self._fill_observable_object_attribute(
                f'{reference} - {relation} - {address.value}',
                observed_data_id
            )
        )
        if hasattr(address, 'display_name'):
            misp_object.add_attribute(
                f'{relation}-display-name', address.display_name,
                **self._fill_observable_object_attribute(
                    f'{reference} - {relation}-display-name - {address.display_name}',
                    observed_data_id
                )
            )

    def _parse_email_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        email_ids = tuple(
            self._filter_observable_objects(observable_objects, 'email-message')
        )
        feature = 'observable' if len(email_ids) > 1 else 'single_observable'
        for email_id in email_ids:
            email_message = observable_objects[email_id]
            if self._force_observable_as_object(email_message, 'email'):
                self._parse_email_observable_object(
                    email_message, email_id, observed_data, observable_objects
                )
                continue
            for field in self._get_populated_properties(email_message):
                attribute = self._mapping.email_message_mapping(field)
                if attribute is not None:
                    self._add_misp_attribute(
                        getattr(self, f'_handle_{feature}_attribute')(
                            email_message, field, attribute['type'],
                            observed_data.id
                        ),
                        observed_data
                    )
                    break
                # The only remaining field that is supported in the conversion
                # mapping at this point should be `additional_header_fields`
                if field == 'additional_header_fields':
                    header_fields = email_message.additional_header_fields
                    if 'Reply-To' in header_fields:
                        self._add_misp_attribute(
                            getattr(self, f'_handle_{feature}_attribute')(
                                header_fields, 'Reply-To', 'email-reply-to',
                                observed_data.id
                            ),
                            observed_data
                        )
                        break
                    if 'X-Mailer' in header_fields:
                        self._add_misp_attribute(
                            getattr(self, f'_handle_{feature}_attribute')(
                                header_fields, 'X-Mailer', 'email-x-mailer',
                                observed_data.id
                            ),
                            observed_data
                        )
                        break

    def _parse_file_observable_object(
            self, file_object: _FILE_TYPING, object_id: str, references: dict,
            reference: str, observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object_from_observable(
            'file', file_object, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'file_object_mapping', file_object, misp_object,
            reference, observed_data.id
        )
        if hasattr(file_object, 'hashes'):
            self._populate_object_attributes_from_observable(
                'file_hashes_object_mapping', file_object.hashes, misp_object,
                reference, observed_data.id
            )
        if hasattr(file_object, 'parent_directory_ref'):
            directory = references[file_object.parent_directory_ref]
            misp_object.add_attribute(
                'path', directory.path,
                **self._fill_observable_object_attribute(
                    f'{reference} - path - {directory.path}',
                    observed_data.id
                )
            )
        # content_ref still to parse...
        return self._add_misp_object(misp_object, observed_data)

    def _parse_file_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        file_ids = tuple(
            self._filter_observable_objects(observable_objects, 'file')
        )
        feature = 'observable' if len(file_ids) > 1 else 'single_observable'
        mapping = {}
        for object_id, observable_object in observable_objects.items():
            if object_id not in mapping:
                object_type = observable_object.type
                mapping[object_id] = getattr(
                    self, f'_parse_{object_type}_observables'
                )(
                    object_id, observable_objects, mapping,
                    feature, observed_data
                )

    def _parse_file_observables(
            self, object_id: str, observable_objects: dict, mapping: dict,
            feature: str, observed_data: _OBSERVED_DATA_TYPING) -> str:
        file_object = observable_objects[object_id]
        if self._force_observable_as_object(file_object, 'file'):
            reference = getattr(
                file_object, 'id', f'{observed_data.id} - {object_id}'
            )
            misp_object = self._parse_file_observable_object(
                file_object, object_id, observable_objects,
                reference, observed_data
            )
            if hasattr(file_object, 'extensions'):
                if 'windows-pebinary-ext' in file_object.extensions:
                    misp_object.add_reference(
                        self._parse_file_pe_extension(
                            file_object.extensions['windows-pebinary-ext'],
                            reference, observed_data
                        ),
                        'includes'
                    )
            if hasattr(file_object, 'contains_refs'):
                for contains_ref in file_object.contains_refs:
                    if contains_ref not in observable_objects:
                        continue
                    if contains_ref in mapping:
                        misp_object.add_reference(
                            mapping[contains_ref], 'contains'
                        )
                        continue
                    contained_object_uuid = self._parse_file_observables(
                        contains_ref, observable_objects, mapping,
                        feature, observed_data
                    )
                    mapping[contains_ref] = contained_object_uuid
                    misp_object.add_reference(
                        contained_object_uuid, 'contains'
                    )
            return misp_object.uuid
        for field in self._get_populated_properties(file_object):
            attribute = self._mapping.file_object_mapping(field)
            if attribute is not None:
                misp_attribute = self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_attribute')(
                        file_object, field, attribute['type'], observed_data.id
                    ),
                    observed_data
                )
                return misp_attribute.uuid
            attribute = self._mapping.file_hashes_object_mapping(field)
            if attribute is not None:
                misp_attribute = self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_attribute')(
                        file_object, field, attribute['type'], observed_data.id
                    ),
                    observed_data
                )
                return misp_attribute.uuid

    def _parse_file_pe_extension(
            self, extension: _PE_EXTENSION_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> str:
        reference = f'{object_id} - {extension._type}'
        misp_object = self._create_misp_object_from_observable_without_id(
            'pe', reference, observed_data
        )
        self._populate_object_attributes_from_observable(
            'pe_object_mapping', extension, misp_object,
            reference, observed_data.id
        )
        if hasattr(extension, 'optional_header'):
            self._populate_object_attributes_from_observable(
                'pe_optional_header_object_mapping', extension, misp_object,
                reference, observed_data.id
            )
        pe_object = self._add_misp_object(misp_object, observed_data)
        if hasattr(extension, 'sections'):
            for section_id, section in enumerate(extension.sections):
                section_reference = f'{reference} - {section_id}'
                section_object = self._create_misp_object_from_observable_without_id(
                    'pe-section', section_reference, observed_data
                )
                self._populate_object_attributes_from_observable(
                    'pe_section_object_mapping', section, section_object,
                    section_reference, observed_data.id
                )
                if hasattr(section, 'hashes'):
                    self._populate_object_attributes_from_observable(
                        'file_hashes_object_mapping', section.hashes, section_object,
                        section_reference, observed_data.id
                    )
                self._add_misp_object(section_object, observed_data)
                pe_object.add_reference(section_object.uuid, 'includes')
        return pe_object.uuid

    def _parse_generic_observables(
            self, observed_data: _OBSERVED_DATA_TYPING, feature: str,
            attribute_type: str, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, observable_object in observable_objects.items():
            self._add_misp_attribute(
                self._handle_observable_attribute(
                    observable_object, feature, attribute_type,
                    observed_data.id, object_id
                ),
                observed_data
            )

    def _parse_generic_single_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, feature: str,
            attribute_type: str, asset: str):
        observable_object = next(
            getattr(self, f'_fetch_observable_{asset}')(observed_data)
        )
        self._add_misp_attribute(
            self._handle_single_observable_attribute(
                observable_object, feature, attribute_type, observed_data.id
            ),
            observed_data
        )

    def _parse_ip_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_generic_observables(
                observed_data, 'value', 'ip-dst', asset
            )
        else:
            self._parse_generic_single_observable(
                observed_data, 'value', 'ip-dst', asset
            )

    def _parse_mac_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_generic_observables(
                observed_data, 'value', 'mac-address', asset
            )
        else:
            self._parse_generic_single_observable(
                observed_data, 'value', 'mac-address', asset
            )

    def _parse_mutex_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_generic_observables(
                observed_data, 'name', 'mutex', asset
            )
        else:
            self._parse_generic_single_observable(
                observed_data, 'name', 'mutex', asset
            )

    def _parse_network_connection_observable_object(
            self, network_traffic: _NETWORK_TRAFFIC_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        reference = getattr(
            network_traffic, 'id', f'{observed_data.id} - {object_id}'
        )
        misp_object = self._parse_network_traffic_observable_object(
            'network-connection', network_traffic, object_id,
            observed_data, reference
        )
        for index, protocol in enumerate(network_traffic.protocols):
            layer = self._mapping.connection_protocols(protocol)
            if layer is not None:
                misp_object.add_attribute(
                    f'layer{layer}-protocol', protocol,
                    **self._fill_observable_object_attribute(
                        f'{reference} - {index} - layer{layer}'
                        f'-protocol - {protocol}',
                        observed_data.id
                    )
                )
        return misp_object

    def _parse_network_socket_observable_object(
            self, network_traffic: _NETWORK_TRAFFIC_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        reference = getattr(
            network_traffic, 'id', f'{observed_data.id} - {object_id}'
        )
        misp_object = self._parse_network_traffic_observable_object(
            'network-socket', network_traffic, object_id,
            observed_data, reference
        )
        socket_extension = network_traffic.extensions['socket-ext']
        self._populate_object_attributes_from_observable(
            'network_socket_extension_object_mapping', socket_extension,
            misp_object, reference, observed_data.id
        )
        for index, protocol in enumerate(network_traffic.protocols):
            misp_object.add_attribute(
                'protocol', protocol,
                **self._fill_observable_object_attribute(
                    f'{reference} - {index} - protocol - {protocol}',
                    observed_data.id
                )
            )
        for feature in ('blocking', 'listening'):
            if getattr(socket_extension, f'is_{feature}', False):
                misp_object.add_attribute(
                    'state', feature,
                    **self._fill_observable_object_attribute(
                        f'{reference} - state - {feature}',
                        observed_data.id
                    )
                )
        return misp_object

    @staticmethod
    def _parse_network_traffic_observable_fields(
            network_traffic: _NETWORK_TRAFFIC_TYPING) -> str:
        if getattr(network_traffic, 'extensions', {}).get('socket-ext'):
            return 'network_socket'
        return 'network_connection'

    def _parse_network_traffic_observable_object(
            self, name: str, network_traffic: _NETWORK_TRAFFIC_TYPING,
            object_id: str, observed_data: _OBSERVED_DATA_TYPING,
            reference: str) -> MISPObject:
        misp_object = self._create_misp_object_from_observable(
            name, network_traffic, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'network_traffic_object_mapping', network_traffic,
            misp_object, reference, observed_data.id
        )
        return misp_object

    def _parse_network_traffic_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        network_traffic_ids = tuple(
            self._filter_observable_objects(observable_objects, 'netork-traffic')
        )
        mapping = {}
        for nt_id in network_traffic_ids:
            if nt_id not in mapping:
                mapping[nt_id] = self._parse_network_traffic_observables(
                    nt_id, observable_objects, mapping, observed_data
                )

    def _parse_network_traffic_observables(
            self, object_id: str, observable_objects: dict, mapping: dict,
            observed_data: _OBSERVED_DATA_TYPING) -> str:
        network_traffic = observable_objects[object_id]
        name = self._parse_network_traffic_observable_fields(network_traffic)
        misp_object = getattr(self, f'_parse_{name}_observable_object')(
            network_traffic, object_id, observed_data
        )
        for asset in ('src', 'dst'):
            if hasattr(network_traffic, f'{asset}_ref'):
                referenced_id = getattr(network_traffic, f'{asset}_ref')
                referenced_object = observable_objects[referenced_id]
                reference = getattr(
                    referenced_object, 'id',
                    f'{observed_data.id} - {referenced_id}'
                )
                relation = getattr(
                    self._mapping, f'{name}_object_reference_mapping'
                )(
                    f"{referenced_object.type.split('-')[0]}-{asset}"
                )
                if relation is None:
                    continue
                misp_object.add_attribute(
                    relation, referenced_object.value,
                    **self._fill_observable_object_attribute(
                        f"{reference} - {relation} - {referenced_object.value}",

                    )
                )
        misp_object = self._add_misp_object(misp_object, observed_data)
        if hasattr(network_traffic, 'encapsulates_refs'):
            for referenced_id in network_traffic.encapsulates_refs:
                if referenced_id in mapping:
                    misp_object.add_reference(
                        mapping[referenced_id], 'encapsulates'
                    )
                    continue
                referenced_uuid = self._parse_network_traffic_observables(
                    referenced_id, observable_objects, mapping, observed_data
                )
                mapping[referenced_id] = referenced_uuid
                misp_object.add_reference(referenced_uuid, 'encapsulates')
        if hasattr(network_traffic, 'encapsulated_by_ref'):
            referenced_id = network_traffic.encapsulated_by_ref
            if referenced_id in mapping:
                misp_object.add_reference(
                    mapping[referenced_id], 'encapsulated-by'
                )
                return misp_object.uuid
            referenced_uuid = self._parse_network_traffic_observables(
                referenced_id, observable_objects, mapping, observed_data
            )
            mapping[referenced_id] = referenced_uuid
            misp_object.add_reference(referenced_uuid, 'encapsulated-by')
        return misp_object.uuid

    def _parse_process_observable_object(
            self, process: _PROCESS_TYPING, process_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        reference = getattr(process, 'id', f'{observed_data.id} - {process_id}')
        misp_object = self._create_misp_object_from_observable(
            'process', process, process_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'process_object_mapping', process, misp_object,
            reference, observed_data.id
        )
        if hasattr(process, 'environment_variables'):
            value = ' '.join(
                f'{key} {value}' for key, value in
                process.environment_variables.items()
            )
            misp_object.add_attribute(
                'args', value,
                **self._fill_observable_object_attribute(
                    f'{reference} - args - {value}', observed_data.id
                )
            )
        elif hasattr(process, 'arguments'):
            value = ' '.join(process.arguments)
            misp_object.add_attribute(
                'args', value,
                **self._fill_observable_object_attribute(
                    f'{reference} - args - {value}', observed_data.id
                )
            )
        return self._add_misp_object(misp_object, observed_data)

    def _parse_process_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        observable_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        process_ids = tuple(
            self._filter_observable_objects(observable_objects, 'process')
        )
        mapping = {}
        for process_id in process_ids:
            if process_id not in mapping:
                mapping[process_id] = self._parse_process_observables(
                    process_id, observable_objects, mapping, observed_data
                )

    def _parse_process_observables(
            self, process_id: str, observable_objects: dict, mapping: dict,
            observed_data: _OBSERVED_DATA_TYPING) -> str:
        process = observable_objects[process_id]
        misp_object = self._parse_process_observable_object(
            process, process_id, observed_data
        )
        if hasattr(process, 'parent_ref'):
            parent_ref = process.parent_ref
            if parent_ref in observable_objects:
                if parent_ref in mapping:
                    misp_object.add_reference(mapping[parent_ref], 'child-of')
                else:
                    parent_uuid = self._parse_process_observables(
                        parent_ref, observable_objects, mapping, observed_data
                    )
                    mapping[parent_ref] = parent_uuid
                    misp_object.add_reference(parent_uuid, 'child-of')
        if hasattr(process, 'child_refs'):
            for child_ref in process.child_refs:
                if child_ref not in observable_objects:
                    continue
                if child_ref in mapping:
                    misp_object.add_reference(mapping[child_ref], 'parent-of')
                    continue
                child_uuid = self._parse_process_observables(
                    child_ref, observable_objects, mapping, observed_data
                )
                mapping[child_ref] = child_uuid
                misp_object.add_reference(child_uuid, 'parent-of')
        if hasattr(process, 'image_ref'):
            image_ref = process.image_ref
            if image_ref in observable_objects:
                if image_ref in mapping:
                    misp_object.add_reference(mapping[image_ref], 'executes')
                else:
                    image_uuid = self._parse_file_observables(
                        image_ref, observable_objects, mapping,
                        'observable', observed_data
                    )
                    mapping[image_ref] = image_uuid
                    misp_object.add_reference(image_uuid, 'executes')
        return misp_object.uuid

    def _parse_registry_key_observable_object(
            self, registry_key: _REGISTRY_KEY_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING):
        reference = getattr(
            registry_key, 'id', f'{observed_data.id} - {object_id}'
        )
        misp_object = self._create_misp_object_from_observable(
            'registry-key', registry_key, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'registry_key_object_mapping', registry_key, misp_object,
            reference, observed_data.id
        )
        if 'values' not in registry_key.properties_populated():
            return self._add_misp_object(misp_object, observed_data)
        if len(registry_key['values']) == 1:
            self._populate_object_attributes_from_observable(
                'registry_key_values_object_mapping', registry_key['values'],
                misp_object, reference, observed_data.id
            )
            return self._add_misp_object(misp_object, observed_data)
        registry_key_object = self._add_misp_object(misp_object, observed_data)
        for index, registry_value in enumerate(registry_key['values']):
            value_reference = f'{reference} - values - {index}'
            value_object = self._create_misp_object('registry-key-value')
            value_object.from_dict(
                uuid=self._create_v5_uuid(value_reference),
                comment=f'Original Observed Data ID: {observed_data.id}',
                **self._parse_timeline(observed_data)
            )
            self._populate_object_attributes_from_observable(
                'registry_key_values_object_mapping', registry_value,
                value_object, value_reference, observed_data.id
            )
            self._add_misp_object(value_object, observed_data)
            registry_key_object.add_reference(value_object.uuid, 'contains')

    def _parse_registry_key_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        registry_keys = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        feature = 'observable' if len(registry_keys) > 1 else 'single_observable'
        for object_id, registry_key in registry_keys.items():
            if self._force_observable_as_object(registry_key, 'registry_key'):
                self._parse_registry_key_observable_object(
                    registry_key, object_id, observed_data
                )
                continue
            if 'values' in registry_key.properties_populated():
                self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_special_attribute')(
                        registry_key,
                        f"{registry_key.key}|{registry_key['values'][0]['data']}",
                        'regkey|value', observed_data.id
                    ),
                    observed_data
                )
                continue
            # Potential exception here is the registry key object has no key
            self._add_misp_attribute(
                getattr(self, f'_handle_{feature}_attribute')(
                    registry_key, 'key', 'regkey', observed_data.id
                ),
                observed_data
            )

    def _parse_software_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        softwares = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, software in softwares.items():
            reference = getattr(
                software, 'id', f'{observed_data.id} - {object_id}'
            )
            misp_object = self._create_misp_object_from_observable(
                'software', software, object_id, observed_data
            )
            self._populate_object_attributes_from_observable(
                'software_object_mapping', software, misp_object,
                reference, observed_data.id
            )
            if hasattr(software, 'languages'):
                for index, language in enumerate(software.languages):
                    misp_object.add_attribute(
                        'language', language,
                        **self._fill_observable_object_attribute(
                            f'{reference} - languages - {index}',
                            observed_data.id
                        )
                    )
            self._add_misp_object(misp_object, observed_data)

    def _parse_url_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        if len(getattr(observed_data, asset)) > 1:
            self._parse_generic_observables(
                observed_data, 'value', 'url', asset
            )
        else:
            self._parse_generic_single_observable(
                observed_data, 'value', 'url', asset
            )

    def _parse_user_account_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        user_accounts = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, user_account in user_accounts.items():
            reference = getattr(
                user_account, 'id', f'{observed_data.id} - {object_id}'
            )
            misp_object = self._create_misp_object_from_observable(
                'user-account', user_account, object_id, observed_data
            )
            self._populate_object_attributes_from_observable(
                'user_account_object_mapping', user_account, misp_object,
                reference, observed_data.id
            )
            if 'unix-account-ext' in getattr(user_account, 'extensions', {}):
                self._populate_object_attributes_from_observable(
                    'user_account_unix_extension_object_mapping',
                    user_account.extensions['unix-account-ext'],
                    misp_object, reference, observed_data.id
                )
            self._add_misp_object(misp_object, observed_data)

    def _parse_x509_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING, asset: str):
        x509_objects = dict(
            getattr(self, f'_fetch_observable_{asset}_with_id')(observed_data)
        )
        for object_id, x509_object in x509_objects.items():
            reference = getattr(
                x509_object, 'id', f'{observed_data.id} - {object_id}'
            )
            misp_object = self._create_misp_object_from_observable(
                'x509-certificate', x509_object, object_id, observed_data
            )
            if hasattr(x509_object, 'hashes'):
                self._populate_object_attributes_from_observable(
                    'x509_hashes_object_mapping', x509_object.hashes,
                    misp_object, reference, observed_data.id
                )
            self._populate_object_attributes_from_observable(
                'x509_object_mapping', x509_object, misp_object,
                reference, observed_data.id
            )
            self._add_misp_object(misp_object, observed_data)

    def _populate_object_attributes_from_observable(
            self, feature: str, observable_object: _OBSERVABLE_OBJECTS_TYPING,
            misp_object: MISPObject, reference: str, observed_data_id: str):
        for field, attribute in getattr(self._mapping, feature)().items():
            if observable_object.get(field):
                value = getattr(
                    observable_object, field, observable_object[field]
                )
                misp_object.add_attribute(
                    **{
                        'value': value, **attribute,
                        **self._fill_observable_object_attribute(
                            f"{reference} - {attribute['object_relation']}"
                            f' - {value}', observed_data_id
                        )
                    }
                )

    ################################################################################
    #                   MISP DATA STRUCTURES CREATION FUNCTIONS.                   #
    ################################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        return super()._create_attribute_dict(stix_object)

    def _create_misp_object_from_observable(
            self, name: str, observable_object: _OBSERVABLE_OBJECTS_TYPING,
            object_id: str, observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        if hasattr(observable_object, 'id'):
            return self._create_misp_object_from_observable_with_id(
                name, observable_object.id, observed_data
            )
        return self._create_misp_object_from_observable_without_id(
            name, object_id, observed_data
        )

    def _create_misp_object_from_observable_with_id(
            self, name: str, observable_object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object(name)
        self._sanitise_object_uuid(misp_object, observable_object_id)
        misp_object.from_dict(**self._parse_timeline(observed_data))
        return misp_object

    def _create_misp_object_from_observable_without_id(
            self, name: str, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object(name)
        misp_object.from_dict(
            uuid=self._create_v5_uuid(f'{observed_data.id} - {object_id}'),
            comment=f'Original Observed Data ID: {observed_data.id}',
            **self._parse_timeline(observed_data)
        )
        return misp_object

    def _create_misp_object_from_single_observable(
            self, name: str, observable_object: _OBSERVABLE_OBJECTS_TYPING,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        if hasattr(observable_object, 'id'):
            return self._create_misp_object_from_observable_with_id(
                name, observable_object.id, observed_data
            )
        return self._create_misp_object(name, stix_object=observed_data)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _check_existing_galaxy_name(self, stix_object_name: str) -> Union[list, None]:
        if stix_object_name in self.synonyms_mapping:
            return self.synonyms_mapping[stix_object_name]
        for name, tag_names in self.synonyms_mapping.items():
            if stix_object_name in name:
                return tag_names

    @staticmethod
    def _extract_types_from_observables(observed_data: _OBSERVED_DATA_TYPING) -> tuple:
        if hasattr(observed_data, 'object_refs'):
            return 'refs', [
                ref.split('--')[0] for ref in observed_data.object_refs
            ]
        return 'objects', [
            observable.type for observable in observed_data.objects.values()
        ]

    @staticmethod
    def _get_populated_properties(observable_object: _OBSERVABLE_OBJECTS_TYPING):
        for field in observable_object.properties_populated():
            if field not in _observable_skip_properties:
                yield field

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            if reference.get('external_id'):
                meta['external_id'].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _is_pattern_too_complex(self, pattern: str) -> bool:
        if any(keyword in pattern for keyword in self._mapping.pattern_forbidden_relations()):
            return True
        if ' AND ' in pattern and ' OR ' in pattern:
            return True
        return False
