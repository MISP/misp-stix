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
    _IDENTITY_TYPING, _SDO_TYPING, _VULNERABILITY_TYPING)
from pathlib import Path
from pymisp import MISPAttribute, MISPGalaxy, MISPObject
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, CourseOfAction as CourseOfAction_v20,
    ObservedData as ObservedData_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, CourseOfAction as CourseOfAction_v21,
    Indicator as Indicator_v21, Location, ObservedData as ObservedData_v21,
    Vulnerability as Vulnerability_v21)
from stix2patterns.inspector import _PatternData as PatternData
from typing import Optional, Union

# Attack Pattern, Course of Action & Vulnerability objects are obviously not
# Observable objects but they're parsed at some point the same way
_OBSERVABLE_OBJECTS_TYPING = Union[
    AttackPattern_v20,
    AttackPattern_v21,
    CourseOfAction_v20,
    CourseOfAction_v21,
    Vulnerability_v20,
    Vulnerability_v21
]


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, galaxies_as_tags: Optional[bool] = False):
        super().__init__(galaxies_as_tags)
        self._mapping = ExternalSTIX2toMISPMapping()

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

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

    def _handle_observable_mapping(self, observed_data: ObservedData_v21) -> str:
        """
        Takes a STIX 2.1 Observed Data object and redirects to the appropriate
        parsing function depending on the observable objects fields used: objects or
        object_refs.

        :param observed_data: A STIX 2.1 Observed Data object
        :return: The name of the parsing function which should be used to convert
            observable objects and their related observable objects into MISP
            attributes or objects
        """
        if hasattr(observed_data, 'object_refs'):
            return self._handle_observable_refs_mapping(observed_data.object_refs)
        return self._handle_observable_objects_mapping(observed_data.objects)

    def _handle_observable_objects_mapping(self, observable_objects: dict) -> str:
        """
        Takes Observable objects to extract each observable object type in order to
        build a tuple which will be used to map with the appropriate parsing
        function.

        :param observable_objects: Observable objects as a dict like preconised by
            the STIX 2.0 standard. Could be either STIX 2.0 or STIX 2.1 (deprecated)
            observable objects.
        :return: The name of the parsing function mapped from the observable objects
            types extracted from the observable objects
        """
        observable_types = self._extract_types_from_observable_objects(observable_objects)
        try:
            feature = self._mapping.observable_mapping[observable_types]
        except KeyError:
            raise UnknownObservableMappingError(observable_types)
        return f'{feature}_objects'

    def _handle_observable_refs_mapping(self, observable_refs: list) -> str:
        """
        Takes Observable object references to extract each observable object type
        from the references observable objects in order to build a tuple which will
        be used to map with the appropriate parsing function.

        :param observable_refs: List of observable object ids referenced by an
            observed data object
        :return: The name of the parsing function mapped from the observable objects
            types extracted from the referenced observable objects.
        """
        observable_types = self._extract_types_from_observable_refs(observable_refs)
        try:
            feature = self._mapping.observable_mapping[observable_types]
        except KeyError:
            raise UnknownObservableMappingError(observable_types)
        return f'{feature}_refs'

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
        attributes = self._get_attributes_from_observable(
            course_of_action,
            'course_of_action_object_mapping'
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
            tags = tuple(self._parse_markings(identity.object_marking_refs))
            for attribute in misp_object.attributes:
                for tag in tags:
                    attribute.add_tag(tag)
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
                misp_object = self._parse_location_object(location)
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

    def _parse_observed_data_v20(self, observed_data: ObservedData_v20):
        """
        STIX 2.0 Observed Data parsing function. Gets the parsing function depending
        on the observable object types found within the observable objects, and
        simply calls the parsing function that will simply parse the observable
        objects, create the appropriate MISP data structure and add it to the
        associated MISP event.

        :param observed_data: The STIX 2.0 Observed Data object to parse
        """
        feature = self._handle_observable_objects_mapping(observed_data.objects)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_observed_data_v21(self, observed_data: ObservedData_v21):
        """
        STIX 2.1 Observed Data parsing function. Gets the parsing function depending
        on the observable object types found either within the observable objects
        referenced in the object_refs fields, or the observable objects embedded in
        the observed data. It simply calls the parsing function then in order to
        parse the observed data and its related observable objects, and create the
        appropriate MISP data structure that will be added to the associate MISP
        event.

        :param observed_data: The STIX 2.1 Observed Data object to parse
        """
        feature = self._handle_observable_mapping(observed_data)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

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
        attributes = self._get_attributes_from_observable(vulnerability, 'vulnerability_object_mapping')
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

    def _get_attributes_from_observable(self, stix_object: _OBSERVABLE_OBJECTS_TYPING, mapping: str) -> list:
        attributes = []
        for feature, attribute in getattr(self._mapping, mapping).items():
            if hasattr(stix_object, feature):
                misp_attribute = {'value': getattr(stix_object, feature)}
                misp_attribute.update(attribute)
                attributes.append(misp_attribute)
        return attributes

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
        self._handle_import_case(indicator, attributes, 'ip-port')

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
            tags = tuple(self._parse_markings(indicator.object_marking_refs))
            for attribute in misp_object.attributes:
                for tag in tags:
                    attribute.add_tag(tag)
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
                hash_type = identifiers[1].lower().replace('-', '')
                attributes.append(
                    {
                        'type': f'x509-fingerprint-{hash_type}',
                        'object_relation': f'x509-fingerprint-{hash_type}',
                        'value': value
                    }
                )
                continue
            if identifiers[0] in self._mapping.x509_pattern_mapping:
                attribute = {'value': value}
                attribute.update(self._mapping.x509_pattern_mapping[identifiers[0]])
                attributes.append(attribute)
            else:
                self._unmapped_pattern_warning(indicator.id, '.'.join(identifiers))
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
                tags = tuple(self._parse_markings(indicator.object_marking_refs))
                for attribute in misp_object.attributes:
                    for tag in tags:
                        attribute.add_tag(tag)
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

    def _add_misp_attribute(self, attribute: dict, confidence: Optional[int] = None):
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        if confidence is not None:
            misp_attribute.add_tag(self._parse_confidence_level(confidence))
        self.misp_event.add_attribute(**misp_attribute)

    def _add_misp_object(self, misp_object: MISPObject, confidence: Optional[int] = None):
        if confidence is not None:
            confidence_tag = self._parse_confidence_level(confidence)
            for attribute in misp_object.attributes:
                attribute.add_tag(confidence_tag)
        self.misp_event.add_object(misp_object)

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        return super()._create_attribute_dict(stix_object)

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
    def _extract_types_from_observable_objects(observable_objects: dict) -> list:
        return '_'.join(
            sorted(
                {observable.type for observable in observable_objects.values()}
            )
        )

    def _extract_types_from_observable_refs(self, observable_refs: list) -> list:
        return '_'.join(
            sorted(
                {self._observable[object_ref].type for object_ref in observable_refs}
            )
        )

    @staticmethod
    def _handle_object_forcing(attributes: list, object_forcing: tuple) -> bool:
        for attribute in attributes:
            if attribute['object_relation'] in object_forcing:
                return True
        return False

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
