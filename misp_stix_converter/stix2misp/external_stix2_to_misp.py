#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .external_stix2_mapping import ExternalSTIX2Mapping
from .stix2_to_misp import (STIX2toMISPParser, _ATTACK_PATTERN_TYPING,
    _COURSE_OF_ACTION_TYPING, _SDO_TYPING, _VULNERABILITY_TYPING)
from misp_stix_converter.stix2misp.exceptions import (UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError, UnknownPatternTypeError)
from stix2.v20.sdo import (CustomObject as CustomObject_v20, Indicator as Indicator_v20,
    ObservedData as ObservedData_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (CustomObject as CustomObject_v21, Indicator as Indicator_v21,
    Note, ObservedData as ObservedData_v21, Vulnerability as Vulnerability_v21)
from typing import Optional, Union

_OBSERVABLE_OBJECTS_TYPING = Union[
    Vulnerability_v20, # Vulnerability object are obviously not Observable objects but
    Vulnerability_v21  # they're parsed at some point the same way Observable objects are
]


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, synonyms_path: Optional[str]=None):
        super().__init__(synonyms_path)
        self._mapping = ExternalSTIX2Mapping()

    ################################################################################
    #                        STIX OBJECTS LOADING FUNCTIONS                        #
    ################################################################################

    def _load_custom_object(self, custom_object: Union[CustomObject_v20, CustomObject_v21]):
        data_to_load = self._build_data_to_load(custom_object)
        try:
            self._custom_object[custom_object.id] = data_to_load
        except AttributeError:
            self._custom_object = {custom_object.id: data_to_load}

    def _load_indicator(self, indicator: Union[Indicator_v20, Indicator_v21]):
        data_to_load = self._build_data_to_load(indicator)
        try:
            self._indicator[indicator.id] = data_to_load
        except AttributeError:
            self._indicator = {indicator.id: data_to_load}

    def _load_note(self, note: Note):
        data_to_load = self._build_data_to_load(note)
        try:
            self._note[note.id] = data_to_load
        except AttributeError:
            self._note = {note.id: data_to_load}

    def _load_observed_data(self, observed_data: Union[ObservedData_v20, ObservedData_v21]):
        data_to_load = self._build_data_to_load(observed_data)
        try:
            self._observed_data[observed_data.id] = data_to_load
        except AttributeError:
            self._observed_data = {observed_data.id: data_to_load}

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _handle_import_case(self, stix_object: _SDO_TYPING, attributes: list, name: str, force_object: Optional[tuple]=None):
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
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self._add_misp_object(misp_object)
        else:
            attribute = self._create_attribute_dict(stix_object)
            attribute.update(attributes[0])
            self._add_misp_attribute(attribute)

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

    def _handle_pattern_mapping(self, indicator: Union[Indicator_v20, Indicator_v21]) -> str:
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
        observable_types = self._extract_types_from_pattern(indicator.pattern)
        try:
            return self._mapping.pattern_mapping[observable_types]
        except KeyError:
            raise UnknownPatternMappingError(observable_types)

    def _parse_attack_pattern(self, attack_pattern_ref: str):
        """
        AttackPattern object parsing function.
        We check if the attack pattern name is a known Galaxy Cluster name and store
        the associated tag names what will be used to populate the Galaxies lists
        within the appropriate MISP data structure (attribute, event).

        :param attack_pattern_ref: The AttackPattern id used to find the related
            AttackPattern object to parse
        """
        attack_pattern = self._get_stix_object(attack_pattern_ref)
        if attack_pattern.id in self._galaxies:
            self._galaxies[attack_pattern.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(attack_pattern.name)
            if tag_names is not None:
                self._galaxies[attack_pattern.id] = {
                    'tag_names': tag_names,
                    'used': {self.misp_event.uuid: False}
                }
            else:
                self._parse_attack_pattern_object(attack_pattern)

    def _parse_attack_pattern_object(self, attack_pattern: _ATTACK_PATTERN_TYPING):
        """
        AttackPattern object conversion as MISP object function.
        We found no match with any Galaxy Cluster name, so we now parse this
        AttackPattern object to generate an attack-pattern MISP object.

        :param attack_pattern: The AttackPattern object to parse
        """
        attributes = self._get_attributes_from_observable(
            attack_pattern,
            'attack_pattern_object_mapping'
        )
        if hasattr(attack_pattern, 'external_references'):
            for reference in attack_pattern.external_references:
                attribute = self._parse_attack_pattern_reference(reference)
                if attribute is not None:
                    attributes.append(attribute)
        if attributes:
            misp_object = self._create_misp_object('attack-pattern', attack_pattern)
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self._add_misp_object(misp_object)
        else:
            self._galaxies[attack_pattern.id] = {
                'tag_names': [f'misp-galaxy:attack-pattern="{attack_pattern.name}"'],
                'used': {self.misp_event.uuid: False}
            }

    def _parse_course_of_action(self, course_of_action_ref: str):
        """
        CourseOfAction object parsing function.
        We check if the course of action name is a known Galaxy Cluster name and
        store the associated tag names what will be used to populate the Galaxies
        lists within the appropriate MISP data structure (attribute, event).

        :param course_of_action_ref: The CourseOfAction id used to find the related
            CourseOfAction object to parse
        """
        course_of_action = self._get_stix_object(course_of_action_ref)
        if course_of_action.id in self._galaxies:
            self._galaxies[course_of_action.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(course_of_action.name)
            if tag_names is not None:
                self._galaxies[course_of_action.id] = {
                    'tag_names': tag_names,
                    'used': {self.misp_event.uuid: False}
                }
            else:
                self._parse_course_of_action_object(course_of_action)

    def _parse_course_of_action_object(self, course_of_action: _COURSE_OF_ACTION_TYPING):
        """
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
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self._add_misp_object(misp_object)
        else:
            self._galaxies[course_of_action.id] = {
                'tag_names': [f'misp-galaxy:course-of-action="{course_of_action.name}"'],
                'used': {self.misp_event.uuid: False}
            }

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
        except UnknownPatternMappingError as error:
            self._unknown_pattern_mapping_warning(indicator.id, error)
            feature = '_create_stix_pattern_object'
        except UnknownPatternTypeError as error:
            self._unknown_pattern_type_error(indicator.id, error)
            return
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(indicator)
        except Exception as exception:
            self._indicator_error(indicator.id, exception)

    def _parse_intrusion_set(self, intrusion_set_ref: str):
        """
        IntrusionSet object parsing function.
        We check if the malware name is a known Galaxy Cluster name and store the
        associated tag names what will be used to populate the Galaxies lists within
        the appropriate MISP data structure (attribute, event).

        :param intrusion_set_ref: The IntrusionSet id used to fing the related
            IntrusionSet object to parse
        """
        intrusion_set = self._get_stix_object(intrusion_set_ref)
        if intrusion_set.id in self._galaxies:
            self._galaxies[intrusion_set.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(intrusion_set.name)
            if tag_names is None:
                tag_names = [f'misp-galaxy:intrusion-set="{intrusion_set.name}"']
            self._galaxies[intrusion_set.id] = {
                'tag_names': tag_names,
                'used': {self.misp_event.uuid: False}
            }

    def _parse_location(self, location_ref: str):
        """
        STIX 2.1 Location object parsing function. A geolocation MISP object is
        created and the different STIX fields are converted into the appropriate
        object attributes (Common with the parent parsing class).

        :param location_ref: The Location id used to find the related Location
            object to parse
        """
        location = self._get_stix_object(location_ref)
        misp_object = self._parse_location_object(location)
        self._add_misp_object(misp_object)

    def _parse_malware(self, malware_ref: str):
        """
        Malware object parsing function.
        We check if the malware name is a known Galaxy Cluster name and store the
        associated tag names what will be used to populate the Galaxies lists within
        the appropriate MISP data structure (attribute, event).

        :param malware_ref: The Malware id used to find the related Malware object
            to parse
        """
        malware = self._get_stix_object(malware_ref)
        if malware.id in self._galaxies:
            self._galaxies[malware.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(malware.name)
            if tag_names is None:
                tag_names = [f'misp-galaxy:malware="{malware.name}"']
            self._galaxies[malware.id] = {
                'tag_names': tag_names,
                'used': {self.misp_event.uuid: False}
            }

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
        We check if the threat actor name is a known Galaxy Cluster name and store
        the associated tag names what will be used to populate the Galaxies lists
        within the appropriate MISP data structure (attribute, event).

        :param threat_actor_ref: The ThreatActor id used to find the related
            ThreatActor object to parse
        """
        threat_actor = self._get_stix_object(threat_actor_ref)
        if threat_actor.id in self._galaxies:
            self._galaxies[threat_actor.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(threat_actor.name)
            if tag_names is None:
                tag_names = [f'misp-galaxy:tool="{threat_actor.name}"']
            self._galaxies[threat_actor.id] = {
                'tag_names': tag_names,
                'used': {self.misp_event.uuid: False}
            }

    def _parse_tool(self, tool_ref: str):
        """
        Tool object parsing function.
        We check if the tool name is a known Galaxy Cluster name and store the
        associated tag names what will be used to populate the Galaxies lists within
        the appropriate MISP data structure (attribute, event).

        :param tool_ref: The Tool id used to find the related Tool object to parse
        """
        tool = self._get_stix_object(tool_ref)
        if tool.id in self._galaxies:
            self._galaxies[tool.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(tool.name)
            if tag_names is None:
                tag_names = [f'misp-galaxy:tool="{tool.name}"']
            self._galaxies[tool.id] = {
                'tag_names': tag_names,
                'used': {self.misp_event.uuid: False}
            }

    def _parse_vulnerability(self, vulnerability_ref: str):
        """
        Vulnerabilty object parsing function.
        If the vulnerability name is a known Galaxy Cluster name, we store the
        associated tag names that will be used afterwards to populate the Galaxies
        lists within the appropriate MISP data structure.
        Otherwise, the vulnerability is parsed and depending on the converted
        attributes, the result is either a MISP attribute or a MISP object.

        :param vulnerability_ref: The Vulnerability id used to find the related
            Vulnerability object to parse
        """
        vulnerability = self._get_stix_object(vulnerability_ref)
        if vulnerability.id in self._galaxies:
            self._galaxies[vulnerability.id]['used'][self.misp_event.uuid] = False
        else:
            tag_names = self._check_existing_galaxy_name(vulnerability.name)
            if tag_names is None:
                self._parse_vulnerability_object(vulnerability)
            else:
                self._galaxies[vulnerability.id] = {
                    'tag_names': tag_names,
                    'used': {self.misp_event.uuid: False}
                }

    def _parse_vulnerability_object(self, vulnerability: _VULNERABILITY_TYPING):
        """
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
            self._galaxies[vulnerability.id] = {
                'tag_names': [f'misp-galaxy:vulnerability="{vulnerability.name}"'],
                'used': {self.misp_event.uuid: False}
            }

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

    def _create_stix_pattern_object(self, indicator: Union[Indicator_v20, Indicator_v21]):
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

    def _parse_sigma_pattern(self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        attribute.update(self._mapping.sigma_attribute)
        self._add_misp_attribute(attribute)

    def _parse_snort_pattern(self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        attribute.update(self._mapping.snort_attribute)
        self._add_misp_attribute(attribute)

    def _parse_suricata_pattern(self, indicator: Indicator_v21):
        misp_object = self._create_misp_object('suricata', indicator)
        for feature, attribute in self._mapping.suricata_object_mapping.items():
            if hasattr(indicator, feature):
                misp_attribute = {'value': getattr(indicator, feature)}
                misp_attribute.update(attribute)
                misp_object.add_attribute(**misp_attribute)
        self._add_misp_object(misp_object)

    def _parse_yara_pattern(self, indicator: Indicator_v21):
        if hasattr(indicator, 'pattern_version'):
            misp_object = self._create_misp_object('yara', indicator)
            for feature, attribute in self._mapping.yara_object_mapping.items():
                if hasattr(indicator, feature):
                    misp_attribute = {'value': getattr(indicator, feature)}
                    misp_attribute.update(attribute)
                    misp_object.add_attribute(**misp_attribute)
            self._add_misp_object(misp_object)
        else:
            attribute = self._create_attribute_dict(indicator)
            attribute['value'] = indicator.pattern
            attribute.update(self._mapping.yara_attribute)
            self._add_misp_attribute(attribute)

    ################################################################################
    #                   MISP DATA STRUCTURES CREATION FUNCTIONS.                   #
    ################################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = {'uuid': stix_object.id.split('--')[-1]}
        attribute.update(self._parse_timeline(stix_object))
        if hasattr(stix_object, 'description') and stix_object.description:
            attribute['comment'] = stix_object.description
        if hasattr(stix_object, 'object_marking_refs'):
            self._update_marking_refs(attribute['uuid'])
        return attribute

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
        return sorted({observable.type for observable in observable_objects.values()})

    def _extract_types_from_observable_refs(self, observable_refs: list) -> list:
        return sorted({self._observable[object_ref].type for object_ref in observable_refs})

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
