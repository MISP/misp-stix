#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import (
    InvalidSTIXPatternError, UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError,
    UnknownPatternTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import _INDICATOR_TYPING
from .stix2_pattern_parser import STIX2PatternParser
from .stix2_to_misp import (
    STIX2toMISPParser, _COURSE_OF_ACTION_TYPING, _GALAXY_OBJECTS_TYPING,
    _IDENTITY_TYPING, _OBSERVED_DATA_TYPING, _SDO_TYPING, _VULNERABILITY_TYPING)
from collections import defaultdict
from pymisp import MISPAttribute, MISPGalaxy, MISPObject
from stix2.v20.observables import (
    AutonomousSystem as AutonomousSystem_v20, Directory as Directory_v20,
    DomainName as DomainName_v20, EmailAddress as EmailAddress_v20,
    EmailMessage as EmailMessage_v20, File as File_v20,
    IPv4Address as IPv4Address_v20, IPv6Address as IPv6Address_v20,
    MACAddress as MACAddress_v20, Mutex as Mutex_v20, Process as Process_v20,
    URL as URL_v20, WindowsPEBinaryExt as WindowsPEBinaryExt_v20,
    X509Certificate as X509Certificate_v20)
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, CourseOfAction as CourseOfAction_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v20.observables import (
    AutonomousSystem as AutonomousSystem_v21, Directory as Directory_v21,
    DomainName as DomainName_v21, EmailAddress as EmailAddress_v21,
    EmailMessage as EmailMessage_v21, File as File_v21,
    IPv4Address as IPv4Address_v21, IPv6Address as IPv6Address_v21,
    MACAddress as MACAddress_v21, Mutex as Mutex_v21, Process as Process_v21,
    URL as URL_v21, WindowsPEBinaryExt as WindowsPEBinaryExt_v21,
    X509Certificate as X509Certificate_v21)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, CourseOfAction as CourseOfAction_v21,
    Indicator as Indicator_v21, Location, ObservedData as ObservedData_v21,
    Vulnerability as Vulnerability_v21)
from stix2patterns.inspector import _PatternData as PatternData
from typing import Optional, Tuple, Union

_observable_skip_properties = (
    'content_ref', 'content_type', 'decryption_key', 'defanged',
    'encryption_algorithm', 'extensions', 'id', 'is_encrypted', 'is_multipart',
    'magic_number_hex', 'received_lines', 'sender_ref', 'spec_version', 'type'
)

_GENERIC_SDO_TYPING = Union[
    CourseOfAction_v20,
    CourseOfAction_v21,
    Vulnerability_v20,
    Vulnerability_v21
]
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
    Process_v20, Process_v21,
    URL_v20, URL_v21,
    WindowsPEBinaryExt_v20, WindowsPEBinaryExt_v21,
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
_URL_TYPING = Union[
    URL_v20, URL_v21
]
_X509_TYPING = Union[
    X509Certificate_v20, X509Certificate_v21
]


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, galaxies_as_tags: Optional[bool] = False):
        super().__init__(galaxies_as_tags)
        self._mapping = ExternalSTIX2toMISPMapping()

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _get_attributes_from_generic_SDO(
            self, stix_object: _GENERIC_SDO_TYPING, mapping: str):
        for feature, attribute in getattr(self._mapping, mapping).items():
            if hasattr(stix_object, feature):
                misp_attribute = {'value': getattr(stix_object, feature)}
                misp_attribute.update(attribute)
                yield misp_attribute

    def _handle_import_case(self, stix_object: _SDO_TYPING, attributes: list,
                            name: str, force_object: Optional[tuple] = None):
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
        if len(attributes) > 1 or (force_object is not None and self._handle_object_forcing(attributes, force_object)):
            misp_object = self._create_misp_object(name, stix_object)
            if hasattr(stix_object, 'object_marking_refs'):
                tags = tuple(
                    self._parse_markings(stix_object.object_marking_refs)
                )
                for attribute in attributes:
                    misp_attribute = misp_object.add_attribute(**attribute)
                    for tag in tags:
                        misp_attribute.add_tag(tag)
            else:
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            self._add_misp_object(
                misp_object,
                confidence=getattr(stix_object, 'confidence', None)
            )
        else:
            attribute = self._create_attribute_dict(stix_object)
            attribute.update(attributes[0])
            self._add_misp_attribute(
                attribute,
                confidence=getattr(stix_object, 'confidence', None)
            )

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
        try:
            return self._mapping.observable_mapping[to_call]
        except KeyError:
            raise UnknownObservableMappingError(to_call)

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

    def _parse_attack_pattern(self, attack_pattern_ref: str):
        """
        AttackPattern object parsing function.
        We check if the attack pattern already has been seen by looking at its
        ID, otherwise we convert it as a MISP Galaxy Cluster.

        :param attack_pattern_ref: The AttackPattern id
        """
        if attack_pattern_ref in self._clusters:
            self._clusters[attack_pattern_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[attack_pattern_ref] = self._parse_galaxy(
                attack_pattern_ref
            )

    def _parse_campaign(self, campaign_ref: str):
        """
        Campaign object parsing function.
        We check if the campaign already has been seen by looking at its ID,
        otherwise we convert it as a MISP Galaxy Cluster

        :param capaign_ref: The Campaign id
        """
        if campaign_ref in self._clusters:
            self._clusters[campaign_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[campaign_ref] = self._parse_galaxy(campaign_ref)

    def _parse_course_of_action(self, course_of_action_ref: str):
        """
        CourseOfAction object parsing function.
        We check if the course of action already has been seen by looking at its
        ID, otherwise we convert it as a MISP Galaxy Cluster.

        :param course_of_action_ref: The CourseOfAction id
        """
        if course_of_action_ref in self._clusters:
            self._clusters[course_of_action_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[course_of_action_ref] = self._parse_galaxy(
                course_of_action_ref
            )

    def _parse_course_of_action_object(self, course_of_action: _COURSE_OF_ACTION_TYPING):
        """
        # Not currently used, but if we can ever make use of the `action` field
        # in the STIX 2 CourseOfAction object, we might use this function again

        CourseOfAction object conversion as MISP object function.
        We found no match with any Galaxy Cluster name, so we now parse this
        CourseOfAction object to generate an attack-pattern MISP object.

        :param course_of_action: The CourseOfAction object to parse
        """
        attributes = tuple(
            self._get_attributes_from_generic_SDO(
                course_of_action, 'course_of_action_object_mapping'
            )
        )
        if attributes:
            misp_object = self._create_misp_object('course-of-action', course_of_action)
            if hasattr(course_of_action, 'object_marking_refs'):
                tags = tuple(
                    self._parse_markings(course_of_action.object_marking_refs)
                )
                for attribute in attributes:
                    misp_attribute = misp_object.add_attribute(**attribute)
                    for tag in tags:
                        misp_attribute.add_tag(tag)
            else:
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            self._add_misp_object(
                misp_object,
                confidence=getattr(course_of_action, 'confidence', None)
            )
        else:
            self._clusters[course_of_action.id] = {
                'tag_names': [f'misp-galaxy:course-of-action="{course_of_action.name}"'],
                'used': {self.misp_event.uuid: False}
            }

    def _parse_galaxy(self, object_ref: str) -> dict:
        object_type = object_ref.split("--")[0]
        stix_object = self._get_stix_object(object_ref)
        name = stix_object.name
        if self.galaxies_as_tags:
            tag_names = self._check_existing_galaxy_name(name)
            if tag_names is None:
                tag_names = [
                    f'misp-galaxy:{object_type}="{name}"'
                ]
            return {
                'tag_names': tag_names,
                'used': {self.misp_event.uuid: False}
            }
        if object_type not in self._galaxies:
            self._galaxies[object_type] = self._create_galaxy_args(stix_object)
        return {
            'cluster': getattr(
                self, f"_parse_{object_type.replace('-', '_')}_cluster"
            )(
                stix_object
            ),
            'used': {self.misp_event.uuid: False}
        }

    def _parse_identity(self, identity_ref: str):
        """
        Identity object parsing function.
        Based on the `identity_class` field, we try to redirect to the
        appropriate parsing function

        :param identity_ref: The Identity id used to find the related Identity
            object to parse
        """
        identity = self._get_stix_object(identity_ref)
        if not hasattr(identity, 'identity_class'):
            self._parse_identity_object(identity)

    def _parse_identity_object(self, identity: _IDENTITY_TYPING):
        """
        Generic Identity object parsing function.
        With the STIX Identity object, we extract the different fields and
        generate a generic MISP identity object.

        :param identity: The Identity object to parse
        """
        misp_object = self._create_misp_object('identity', identity)
        for feature in self._mapping.identity_object_single_fields:
            if hasattr(identity, feature):
                misp_object.add_attribute(feature, getattr(identity, feature))
        for feature in self._mapping.identity_object_multiple_fields:
            if hasattr(identity, feature):
                for value in getattr(identity, feature):
                    misp_object.add_attribute(feature, value)
        if hasattr(identity, 'object_marking_refs'):
            self._handle_object_marking_refs(
                identity.object_marking_refs, misp_object
            )
        self._add_misp_object(
            misp_object,
            confidence=getattr(identity, 'confidence', None)
        )

    def _parse_indicator(self, indicator_ref: str):
        """
        Indicator object parsing function.
        Gets the parsing function depending on the types found within the pattern,
        and simply calls the parsing function that will parse the pattern, create
        the appropriate MISP data structure and add it to the associated MISP event.

        :param indicator_ref: The Indicator id used to find the related Indicator
            object to parse
        """
        indicator = self._get_stix_object(indicator_ref)
        try:
            feature = self._handle_pattern_mapping(indicator)
        except UnknownPatternTypeError as error:
            self._unknown_pattern_type_error(indicator.id, error)
            return
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(indicator)
        except UnknownPatternMappingError as error:
            self._unknown_pattern_mapping_warning(indicator.id, error.__str__())
            self._create_stix_pattern_object(indicator)
        except InvalidSTIXPatternError as error:
            self._invalid_stix_pattern_error(indicator.id, error)
            self._create_stix_pattern_object(indicator)

    def _parse_intrusion_set(self, intrusion_set_ref: str):
        """
        IntrusionSet object parsing function.
        We check if the intrusion set already has been seen by looking at its
        ID, otherwise we convert it as a MISP Galaxy Cluster.

        :param intrusion_set_ref: The IntrusionSet id
        """
        if intrusion_set_ref in self._clusters:
            self._clusters[intrusion_set_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[intrusion_set_ref] = self._parse_galaxy(
                intrusion_set_ref
            )

    def _parse_location(self, location_ref: str):
        """
        STIX 2.1 Location object parsing function. A geolocation MISP object is
        created and the different STIX fields are converted into the appropriate
        object attributes (Common with the parent parsing class).

        :param location_ref: The Location id used to find the related Location
            object to parse
        """
        if location_ref in self._clusters:
            self._clusters[location_ref]['used'][self.misp_event.uuid] = False
        else:
            location = self._get_stix_object(location_ref)
            if any(hasattr(location, feature) for feature in self._mapping.location_object_fields):
                misp_object = self._parse_location_object(
                    location, to_return=True
                )
                self._add_misp_object(
                    misp_object,
                    confidence=getattr(location, 'confidence', None)
                )
            else:
                feature = 'region' if not hasattr(location, 'country') else 'country'
                if self.galaxies_as_tags:
                    tag_names = self._check_existing_galaxy_name(location)
                    if tag_names is None:
                        tag_names = [
                            f'misp-galaxy:{feature}="{location.name}"'
                        ]
                    self._clusters[location.id] = {
                        'tag_names': tag_names,
                        'used': {self.misp_event.uuid: False}
                    }
                else:
                    self._clusters[location.id] = {
                        'cluster': getattr(self, f'_parse_{feature}_cluster')(
                            location
                        ),
                        'used': {self.misp_event.uuid: False}
                    }
                    if feature not in self._galaxies:
                        self._galaxies[feature] = self._create_galaxy_args(
                            location, galaxy_type=feature
                        )

    def _parse_malware(self, malware_ref: str):
        """
        Malware object parsing function.
        We check if the malware already has been seen by looking at its ID,
        otherwise we convert it as a MISP Galaxy Cluster.

        :param malware_ref: The Malware id
        """
        if malware_ref in self._clusters:
            self._clusters[malware_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[malware_ref] = self._parse_galaxy(malware_ref)

    def _parse_observable_objects(self, observed_data: _OBSERVED_DATA_TYPING):
        """
        Observed Data with embedded `objects` field parsing.
        Depending on the Observable object types, we call the appropriate
        parsing function.

        :param observed_data: The Observed Data object
        """
        observable_types = set(
            observable.type for observable in observed_data.objects.values()
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

    def _parse_threat_actor(self, threat_actor_ref: str):
        """
        ThreatActor object parsing function.
        We check if the threat actor already has been seen by looking at its ID,
        otherwise we convert it as a MISP Galaxy Cluster.

        :param threat_actor_ref: The ThreatActor id
        """
        if threat_actor_ref in self._clusters:
            self._clusters[threat_actor_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[threat_actor_ref] = self._parse_galaxy(
                threat_actor_ref
            )

    def _parse_tool(self, tool_ref: str):
        """
        Tool object parsing function.
        We check if the tool already has been seen by looking at its ID,
        otherwise we convert it as a MISP Galaxy Cluster.

        :param tool_ref: The Tool id
        """
        if tool_ref in self._clusters:
            self._clusters[tool_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[tool_ref] = self._parse_galaxy(tool_ref)

    def _parse_vulnerability(self, vulnerability_ref: str):
        """
        Vulnerabilty object parsing function.
        If the vulnerability already has been seen by looking at its ID,
        otherwise we convert it as a MISP Galaxy Cluster.

        :param vulnerability_ref: The Vulnerability id
        """
        if vulnerability_ref in self._clusters:
            self._clusters[vulnerability_ref]['used'][self.misp_event.uuid] = False
        else:
            self._clusters[vulnerability_ref] = self._parse_galaxy(
                vulnerability_ref
            )

    def _parse_vulnerability_object(self, vulnerability: _VULNERABILITY_TYPING):
        """
        # Not currently used, but if we can ever define wether the vulnerability
        # is well known or in progress, we might use this function again for
        # vulnerabilities in progress

        Vulnerability object conversion as MISP attribute or object function.
        We found no match with any Galaxy Cluster name, so we now parse this
        Vulnerability object to extract MISP attributes.
        The extracted attributes are then passed to the handler function that will
        define whether a standalone MISP attribute or a MISP object will be created.

        :param vulnerability: The Vulnerability object to parse
        """
        attributes = tuple(
            self._get_attributes_from_generic_SDO(
                vulnerability, 'vulnerability_object_mapping'
            )
        )
        if hasattr(vulnerability, 'external_references'):
            external_ids = set()
            for reference in vulnerability.external_references:
                if reference['source_name'] in ('cve', 'vulnerability') and reference.get('external_id') is not None:
                    external_ids.add(reference['external_id'])
                elif reference['source_name'] == 'url' and reference.get('url') is not None:
                    attribute = {'value': reference['url']}
                    attribute.update(self._mapping.references_attribute)
                    attributes.append(attribute)
            if len(external_ids) == 1:
                attribute = {'value': list(external_ids)[0]}
                attribute.update(self._mapping.vulnerability_attribute)
                attributes.append(attribute)
            else:
                for external_id in external_ids:
                    attribute = {'value': external_id}
                    feature = 'vulnerability_attribute' if external_id == vulnerability.name else 'references_attribute'
                    attribute.update(getattr(self._mapping, feature))
                    attributes.append(attribute)
        if attributes:
            self._handle_import_case(vulnerability, attributes, 'vulnerability')
        else:
            self._clusters[vulnerability.id] = {
                'cluster': self._parse_vulnerbaility_cluster(vulnerability),
                'used': {self.misp_event.uuid: False}
            }
            if 'vulnerability' not in self._galaxies:
                self._galaxies['vulnerability'] = self._create_galaxy_args(
                    vulnerability
                )

    ################################################################################
    #                 STIX Domain Objects (SDOs) PARSING FUNCTIONS                 #
    ################################################################################

    def _create_galaxy_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                            galaxy_type: Optional[str] = None) -> MISPGalaxy:
        galaxy_args = {
            'type': stix_object.type if galaxy_type is None else galaxy_type
        }
        galaxy_args.update(self._mapping.galaxy_name_mapping[galaxy_args['type']])
        misp_galaxy = MISPGalaxy()
        misp_galaxy.from_dict(**galaxy_args)
        return misp_galaxy

    def _parse_country_cluster(self, location: Location):
        country_args = self._create_cluster_args(location, 'country')
        return self._create_misp_galaxy_cluster(country_args)

    def _parse_region_cluster(self, location: Location):
        region_args = self._create_cluster_args(
            location, 'region',
            cluster_value=self._parse_region_value(location)
        )
        return self._create_misp_galaxy_cluster(region_args)

    def _parse_region_value(self, location: Location) -> str:
        if hasattr(location, 'region'):
            return self._mapping.regions_mapping.get(
                location.region, location.name
            )
        return location.name

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
            if field in self._mapping.email_additional_header_fields_mapping:
                length += len(values) if isinstance(values, list) else 1
        return length > 1

    def _check_file_observable_fields(self, file_object: _FILE_TYPING) -> bool:
        if 'windows-pebinary-ext' in getattr(file_object, 'extensions', {}):
            return True
        fields = [
            field for field in self._mapping.file_object_mapping
            if hasattr(file_object, field)
        ]
        if len(fields) > 1:
            return True
        return len(getattr(file_object, 'hashes', {})) > 1

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
            yield self._observable[reference]

    def _fetch_observable_object_refs_with_id(
            self, observed_data: _OBSERVED_DATA_TYPING):
        for reference in observed_data.object_refs:
            yield reference, self._observable[reference]

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
            object_type: str, references: Optional[dict] = None) -> bool:
        fields = getattr(self._mapping, f'{object_type}_object_fields')
        if any(hasattr(observable_object, field) for field in fields):
            return True
        if references is not None:
            return getattr(self, f'_check_{object_type}_observable_fields')(
                observable_object, references
            )
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
            f'{observed_data_id} - {object_id} - {references}', observed_data_id
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
            self._parse_autonomous_system_observable_objects(observable_objects, observed_data)

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
                self._add_misp_object(
                    misp_object,
                    confidence=getattr(observed_data, 'confidence', None)
                )
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
                confidence=getattr(observed_data, 'confidence', None)
            )
        else:
            self._add_misp_attribute(
                self._handle_observable_special_attribute(
                    autonomous_system, f'AS{autonomous_system.number}',
                    'AS', observed_data.id, object_id
                ),
                confidence=getattr(observed_data, 'confidence', None)
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
                confidence=getattr(observed_data, 'confidence', None)
            )
        else:
            self._add_misp_attribute(
                self._handle_single_observable_special_attribute(
                    autonomous_system, f'AS{autonomous_system.number}',
                    'AS', observed_data.id
                ),
                confidence=getattr(observed_data, 'confidence', None)
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
            'directory', directory, misp_object, reference, observed_data.id
        )
        return self._add_misp_object(
            misp_object, confidence=getattr(observed_data, 'confidence', None)
        )

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
                    confidence=getattr(observed_data, 'confidence', None)
                )
                self._add_misp_attribute(
                    self._create_attribute_from_observable_object(
                        'email-dst-display-name', email_address.display_name,
                        observed_data.id, object_id
                    ),
                    confidence=getattr(observed_data, 'confidence', None)
                )
                continue
            self._add_misp_attribute(
                self._handle_observable_attribute(
                    email_address, 'value', 'email-dst',
                    observed_data.id, object_id
                ),
                confidence=getattr(observed_data, 'confidence', None)
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
                confidence=getattr(observed_data, 'confidence', None)
            )
            self._add_misp_attribute(
                self._create_attribute_from_single_observable_object(
                    'email-dst-display-name', email_address.display_name,
                    observed_data.id
                ),
                confidence=getattr(observed_data, 'confidence', None)
            )
        else:
            self._add_misp_attribute(
                self._handle_single_observable_attribute(
                    email_address, 'value', 'email-dst', observed_data.id
                ),
                confidence=getattr(observed_data, 'confidence', None)
            )

    def _parse_email_observable_object(
            self, email_message: _EMAIL_MESSAGE_TYPING, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING, references: dict,
            reference: str):
        misp_object = self._create_misp_object_from_observable(
            'email', email_message, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'email', email_message, misp_object, reference, observed_data.id
        )
        if getattr(email_message, 'from_ref', None) in references:
            self._parse_email_observable_object_reference(
                misp_object, references[email_message.from_ref], 'from',
                email_message.from_ref, observed_data.id
            )
        for feature in ('to', 'cc', 'bcc'):
            if getattr(email_message, f'{feature}_refs', None) in references:
                for address_ref in getattr(email_message, f'{feature}_refs'):
                    self._parse_email_observable_object_reference(
                        misp_object, references[address_ref], feature,
                        address_ref, observed_data.id
                    )
        if hasattr(email_message, 'additional_header_fields'):
            for field, mapping in self._mapping.email_additional_header_fields_mapping.items():
                if field not in email_message.additional_header_fields:
                    continue
                relation = mapping['object_relation']
                values = email_message.additional_header_fields[field]
                if isinstance(values, list):
                    for index, value in enumerate(values):
                        attribute = {'value': value}
                        attribute.update(mapping)
                        attribute.update(
                            self._fill_observable_object_attribute(
                                f'{reference} - {index} - {relation} - {value}',
                                observed_data.id
                            )
                        )
                        misp_object.add_attribute(**attribute)
                else:
                    attribute = {'value': values}
                    attribute.update(mapping)
                    attribute.update(
                        self._fill_observable_object_attribute(
                            f'{reference} - {relation} - {values}',
                            observed_data.id
                        )
                    )
                    misp_object.add_attribute(**attribute)
        self._add_misp_object(
            misp_object, confidence=getattr(observed_data, 'confidence', None)
        )

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
                reference = getattr(
                    email_message, 'id', f'{observed_data.id} - {email_id}'
                )
                self._parse_email_observable_object(
                    email_message, email_id, observed_data,
                    observable_objects, reference
                )
                continue
            for field in self._get_populated_properties(email_message):
                if field in self._mapping.email_object_mapping:
                    attribute = self._mapping.email_object_mapping[field]
                    self._add_misp_attribute(
                        getattr(self, f'_handle_{feature}_attribute')(
                            email_message, field, attribute['type'],
                            observed_data.id
                        ),
                        confidence=getattr(observed_data, 'confidence', None)
                    )
                    break
                # The only remaining field that is supported in the conversion
                # mapping at this point should be `additional_header_fields`
                if field == 'additional_header_fields':
                    header_fields = email_message.additional_header_fields
                    if 'Reply-To' in header_fields:
                        self._add_attribute(
                            getattr(self, f'_handle_{feature}_attribute')(
                                header_fields, 'Reply-To', 'email-reply-to',
                                observed_data.id
                            ),
                            confidence=getattr(observed_data, 'confidence', None)
                        )
                        break
                    if 'X-Mailer' in header_fields:
                        self._add_attribute(
                            getattr(self, f'_handle_{feature}_attribute')(
                                header_fields, 'X-Mailer', 'email-x-mailer',
                                observed_data.id
                            ),
                            confidence=getattr(observed_data, 'confidence', None)
                        )
                        break

    def _parse_file_observable_object(
            self, file_object: _FILE_TYPING, object_id: str, references: dict,
            reference: str, observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object_from_observable(
            'file', file_object, object_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'file', file_object, misp_object, reference, observed_data.id
        )
        if hasattr(file_object, 'hashes'):
            self._populate_object_attributes_from_observable(
                'file_hashes', file_object.hashes, misp_object,
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
        return self._add_misp_object(
            misp_object, confidence=getattr(observed_data, 'confidence', None)
        )

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
            if field in self._mapping.file_object_mapping:
                attribute = self._mapping.file_object_mapping[field]
                misp_attribute = self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_attribute')(
                        file_object, field, attribute['type'], observed_data.id
                    ),
                    confidence=getattr(observed_data, 'confidence', None)
                )
                return misp_attribute.uuid
            if field in self._mapping.file_hashes_object_mapping:
                attribute = self._mapping.file_hashes_object_mapping[field]
                misp_attribute = self._add_misp_attribute(
                    getattr(self, f'_handle_{feature}_attribute')(
                        file_object, field, attribute['type'], observed_data.id
                    ),
                    confidence=getattr(observed_data, 'confidence', None)
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
            'pe', extension, misp_object, reference, observed_data.id
        )
        pe_object = self._add_misp_object(
            misp_object, confidence=getattr(observed_data, 'confidence', None)
        )
        if hasattr(extension, 'sections'):
            for section_id, section in enumerate(extension.sections):
                section_reference = f'{reference} - {section_id}'
                section_object = self._create_misp_object_from_observable_without_id(
                    'pe-section', section_reference, observed_data
                )
                self._populate_object_attributes_from_observable(
                    'pe_section', section, section_object,
                    section_reference, observed_data.id
                )
                if hasattr(section, 'hashes'):
                    self._populate_object_attributes_from_observable(
                        'file_hashes', section.hashes, section_object,
                        section_reference, observed_data.id
                    )
                self._add_misp_object(
                    section_object,
                    confidence=getattr(observed_data, 'confidence', None)
                )
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
                confidence=getattr(observed_data, 'confidence', None)
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
            confidence=getattr(observed_data, 'confidence', None)
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

    def _parse_process_observable_object(
            self, process: _PROCESS_TYPING, process_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        reference = getattr(process, 'id', f'{observed_data.id} - {process_id}')
        misp_object = self._create_misp_object_from_observable(
            'process', process, process_id, observed_data
        )
        self._populate_object_attributes_from_observable(
            'process', process, misp_object, reference, observed_data.id
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
        return self._add_misp_object(
            misp_object, confidence=getattr(observed_data, 'confidence', None)
        )

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
                'user_account', user_account, misp_object,
                reference, observed_data.id
            )
            if 'unix-account-ext' in getattr(user_account, 'extensions', {}):
                self._populate_object_attributes_from_observable(
                    'user_account_unix_extension',
                    user_account.extensions['unix-account-ext'],
                    misp_object, reference, observed_data.id
                )
            self._add_misp_object(
                misp_object,
                confidence=getattr(observed_data, 'confidence', None)
            )

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
                    'x509_hashes', x509_object.hashes, misp_object,
                    reference, observed_data.id
                )
            self._populate_object_attributes_from_observable(
                'x509', x509_object, misp_object, reference, observed_data.id
            )
            self._add_misp_object(
                misp_object,
                confidence=getattr(observed_data, 'confidence', None)
            )

    def _populate_object_attributes_from_observable(
            self, feature: str, observable_object: _OBSERVABLE_OBJECTS_TYPING,
            misp_object: MISPObject, reference: str, observed_data_id: str):
        mapping = getattr(self._mapping, f'{feature}_object_mapping')
        for field, attr in mapping.items():
            if field in observable_object:
                value = getattr(
                    observable_object, field, observable_object[field]
                )
                attribute = {'value': value}
                attribute.update(attr)
                attribute.update(
                    self._fill_observable_object_attribute(
                        f"{reference} - {attr['object_relation']} - {value}",
                        observed_data_id
                    )
                )
                misp_object.add_attribute(**attribute)

    ################################################################################
    #                          PATTERNS PARSING FUNCTIONS                          #
    ################################################################################

    def _compile_stix_pattern(self, indicator: _INDICATOR_TYPING) -> PatternData:
        try:
            self._pattern_parser.handle_indicator(indicator)
        except AttributeError:
            self._pattern_parser = STIX2PatternParser()
            self._pattern_parser.handle_indicator(indicator)
        if not self._pattern_parser.valid:
            raise InvalidSTIXPatternError(indicator.pattern)
        return self._pattern_parser.pattern

    def _create_stix_pattern_object(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('stix2-pattern', indicator)
        if hasattr(indicator, 'description'):
            misp_object.comment = indicator.description
        misp_object.add_attribute(
            **{
                'type': 'text',
                'object_relation': 'version',
                'value': f"stix {indicator.spec_version if hasattr(indicator, 'spec_version') else '2.0'}"
            }
        )
        misp_object.add_attribute(
            **{
                'type': 'stix2-pattern',
                'object_relation': 'stix2-pattern',
                'value': indicator.pattern
            }
        )
        self._add_misp_object(misp_object)

    def _parse_domain_ip_port_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        features = ('domain-name', 'ipv4-addr', 'ipv6-addr')
        for feature in features:
            if feature in compiled_pattern.comparisons:
                for identifiers, assertion, value in compiled_pattern.comparisons[feature]:
                    if assertion != '=':
                        continue
                    if identifiers[0] != 'value':
                        self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
                        continue
                    attribute = {'value': value}
                    attribute.update(self._mapping.domain_ip_pattern_mapping[feature])
                    attributes.append(attribute)
        types = [key for key in compiled_pattern.comparisons.keys() if key not in features]
        if types:
            self._unknown_pattern_mapping_warning(indicator.id, types)
        if attributes:
            self._handle_import_case(indicator, attributes, 'domain-ip')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_email_address_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for identifiers, assertion, value in compiled_pattern.comparisons['email-addr']:
            if assertion != '=':
                continue
            if identifiers[0] in self._mapping.email_address_pattern_mapping:
                attribute = {'value': value}
                attribute.update(
                    self._mapping.email_address_pattern_mapping[identifiers[0]]
                )
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
        if attributes:
            self._handle_import_case(indicator, attributes, 'email')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_email_message_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for identifiers, assertion, value in compiled_pattern.comparisons['email-message']:
            if assertion != '=':
                continue
            if identifiers[0] in self._mapping.email_message_pattern_mapping:
                attribute = {'value': value}
                attribute.update(
                    self._mapping.email_message_pattern_mapping[identifiers[0]]
                )
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
        if attributes:
            self._handle_import_case(indicator, attributes, 'file')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_file_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        if 'file' in compiled_pattern.comparisons:
            for identifiers, assertion, value in compiled_pattern.comparisons['file']:
                if assertion != '=':
                    continue
                if 'hashes' in identifiers:
                    hash_type = identifiers[1].lower().replace('-', '')
                    attributes.append(
                        {
                            'type': hash_type,
                            'object_relation': hash_type,
                            'value': value
                        }
                    )
                    continue
                if identifiers[0] in self._mapping.file_pattern_mapping:
                    attribute = {'value': value}
                    attribute.update(self._mapping.file_pattern_mapping[identifiers[0]])
                    attributes.append(attribute)
                else:
                    self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
        types = [key for key in compiled_pattern.comparisons.keys() if key != 'file']
        if types:
            self._unknown_pattern_mapping_warning(indicator.id, types)
        if attributes:
            self._handle_import_case(indicator, attributes, 'file')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_ip_address_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for feature in ('ipv4-addr', 'ipv6-addr'):
            if feature in compiled_pattern.comparisons:
                for identifiers, assertion, value in compiled_pattern.comparisons[feature]:
                    if assertion != '=':
                        continue
                    if identifiers[0] != 'value':
                        self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
                        continue
                    attribute = {'value': value}
                    attribute.update(self._mapping.ip_attribute)
                    attributes.append(attribute)
        if attributes:
            self._handle_import_case(indicator, attributes, 'ip-port')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_process_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for identifiers, assertion, value in compiled_pattern.comparisons['process']:
            if assertion != '=':
                continue
            if identifiers[0] in self._mapping.process_pattern_mapping:
                attribute = {'value': value}
                attribute.update(self._mapping.process_pattern_mapping[identifiers[0]])
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
        if attributes:
            self._handle_import_case(indicator, attributes, 'process')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_regkey_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for identifiers, assertion, value in compiled_pattern.comparisons['windows-registry-key']:
            if assertion != '=':
                continue
            identifier = identifiers[-1] if 'values' in identifiers else identifiers[0]
            if identifier in self._mapping.regkey_pattern_mapping:
                attribute = {'value': value}
                attribute.update(self._mapping.regkey_pattern_mapping[identifier])
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
        if attributes:
            self._handle_import_case(indicator, attributes, 'registry-key')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_sigma_pattern(self, indicator: Indicator_v21):
        if hasattr(indicator, 'name') or hasattr(indicator, 'external_references'):
            attributes = []
            for feature, mapping in self._mapping.sigma_object_mapping.items():
                if hasattr(indicator, feature):
                    attribute = {'value': getattr(indicator, feature)}
                    attribute.update(mapping)
                    attributes.append(attribute)
            if hasattr(indicator, 'external_references'):
                for reference in indicator.external_references:
                    if not hasattr(reference, 'url'):
                        continue
                    attribute = {'value': reference.url}
                    attribute.update(self._mapping.sigma_reference_attribute)
                    if hasattr(reference, 'description'):
                        attribute['comment'] = reference.description
                    attributes.append(attribute)
            if len(attributes) == 1 and attributes[0]['type'] == 'sigma':
                attribute = self._create_attribute_dict(indicator)
                attribute.update(attributes[0])
                self._add_misp_attribute(
                    attribute,
                    confidence=getattr(indicator, 'confidence', None)
                )
            else:
                misp_object = self._create_misp_object('sigma', indicator)
                if hasattr(indicator, 'object_marking_refs'):
                    tags = tuple(
                        self._parse_markings(indicator.object_marking_refs)
                    )
                    for attribute in attributes:
                        misp_attribute = misp_object.add_attribute(**attribute)
                        for tag in tags:
                            misp_attribute.add_tag(tag)
                else:
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
                self._add_misp_object(
                    misp_object,
                    confidence=getattr(indicator, 'confidence', None)
                )
        else:
            attribute = self._create_attribute_dict(indicator)
            attribute['value'] = indicator.pattern
            attribute.update(self._mapping.sigma_attribute)
            self._add_misp_attribute(
                attribute,
                confidence=getattr(indicator, 'confidence', None)
            )

    def _parse_snort_pattern(self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        attribute.update(self._mapping.snort_attribute)
        self._add_misp_attribute(
            attribute,
            confidence=getattr(indicator, 'confidence', None)
        )

    def _parse_stix_pattern(self, indicator: _INDICATOR_TYPING):
        compiled_pattern = self._compile_stix_pattern(indicator)
        observable_types = '_'.join(sorted(compiled_pattern.comparisons.keys()))
        try:
            feature = self._mapping.pattern_mapping[observable_types]
        except KeyError:
            raise UnknownPatternMappingError(observable_types)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        parser(compiled_pattern, indicator)

    def _parse_suricata_pattern(self, indicator: Indicator_v21):
        misp_object = self._create_misp_object('suricata', indicator)
        for feature, mapping in self._mapping.suricata_object_mapping.items():
            if hasattr(indicator, feature):
                attribute = {'value': getattr(indicator, feature)}
                attribute.update(mapping)
                misp_object.add_attribute(**attribute)
        if hasattr(indicator, 'object_marking_refs'):
            self._handle_marking_refs(
                indicator.object_marking_refs, misp_object
            )
        self._add_misp_object(
            misp_object,
            confidence=getattr(indicator, 'confidence', None)
        )

    def _parse_url_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        if 'url' in compiled_pattern.comparisons:
            for identifiers, assertion, value in compiled_pattern.comparisons['url']:
                if assertion != '=':
                    continue
                if identifiers[0] != 'value':
                    self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
                    continue
                attribute = {'value': value}
                attribute.update(self._mapping.url_attribute)
                attributes.append(attribute)
        types = [key for key in compiled_pattern.comparisons.keys() if key != 'url']
        if types:
            self._unknown_pattern_mapping_warning(indicator.id, types)
        if attributes:
            self._handle_import_case(indicator, attributes, 'url')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_x509_pattern(self, compiled_pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for identifiers, assertion, value in compiled_pattern.comparisons['x509-certificate']:
            if assertion != '=':
                continue
            if 'hashes' in identifiers:
                if identifiers[1] in self._mapping.x509_hashes_object_mapping:
                    hash_type = self._mapping.x509_hashes_object_mapping[
                        identifiers[1]
                    ]
                    attributes.append(
                        {
                            'type': f'x509-fingerprint-{hash_type}',
                            'object_relation': f'x509-fingerprint-{hash_type}',
                            'value': value
                        }
                    )
                continue
            if identifiers[0] in self._mapping.x509_object_mapping:
                attribute = {'value': value}
                attribute.update(
                    self._mapping.x509_object_mapping[identifiers[0]]
                )
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(
                    indicator.id, '.'.join(identifiers)
                )
        if attributes:
            self._handle_import_case(indicator, attributes, 'x509')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_yara_pattern(self, indicator: Indicator_v21):
        if hasattr(indicator, 'pattern_version'):
            misp_object = self._create_misp_object('yara', indicator)
            for feature, mapping in self._mapping.yara_object_mapping.items():
                if hasattr(indicator, feature):
                    attribute = {'value': getattr(indicator, feature)}
                    attribute.update(mapping)
                    misp_object.add_attribute(**attribute)
            if hasattr(indicator, 'external_references'):
                for reference in indicator.external_references:
                    if not hasattr(reference, 'url'):
                        continue
                    attribute = {'value': reference.url}
                    attribute.update(self._mapping.yara_reference_attribute)
                    if hasattr(reference, 'description'):
                        attribute['comment'] = reference.description
                    misp_object.add_attribute(**attribute)
            if hasattr(indicator, 'object_marking_refs'):
                self._handle_object_marking_refs(
                    indicator.object_marking_refs, misp_object
                )
            self._add_misp_object(
                misp_object,
                confidence=getattr(indicator, 'confidence', None)
            )
        else:
            attribute = self._create_attribute_dict(indicator)
            attribute['value'] = indicator.pattern
            attribute.update(self._mapping.yara_attribute)
            self._add_misp_attribute(
                attribute,
                confidence=getattr(indicator, 'confidence', None)
            )

    ################################################################################
    #                   MISP DATA STRUCTURES CREATION FUNCTIONS.                   #
    ################################################################################

    def _add_misp_attribute(
            self, attribute: dict, confidence: Optional[int] = None) -> MISPAttribute:
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        if confidence is not None:
            misp_attribute.add_tag(self._parse_confidence_level(confidence))
        return self.misp_event.add_attribute(**misp_attribute)

    def _add_misp_object(self, misp_object: MISPObject,
                         confidence: Optional[int] = None) -> MISPObject:
        if confidence is not None:
            confidence_tag = self._parse_confidence_level(confidence)
            for attribute in misp_object.attributes:
                attribute.add_tag(confidence_tag)
        return self.misp_event.add_object(misp_object)

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
        misp_object.update(self._parse_timeline(observed_data))
        return misp_object

    def _create_misp_object_from_observable_without_id(
            self, name: str, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object(name)
        misp_object.update(self._parse_timeline(observed_data))
        misp_object.uuid = self._create_v5_uuid(
            f'{observed_data.id} - {object_id}'
        )
        misp_object.comment = f'Original Observed Data ID: {observed_data.id}'
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

    def _is_pattern_too_complex(self, pattern: str) -> bool:
        if any(keyword in pattern for keyword in self._mapping.pattern_forbidden_relations):
            return True
        if all(keyword in pattern for keyword in (' AND ', ' OR ')):
            return True
        return False

    @staticmethod
    def _parse_confidence_level(confidence_level: int) -> str:
        if confidence_level == 100:
            return 'misp:confidence-level="completely-confident"'
        if confidence_level >= 75:
            return 'misp:confidence-level="usually-confident"'
        if confidence_level >= 50:
            return 'misp:confidence-level="fairly-confident"'
        if confidence_level >= 25:
            return 'misp:confidence-level="rarely-confident"'
        return 'misp:confidence-level="unconfident"'
