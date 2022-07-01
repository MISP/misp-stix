#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .external_stix2_mapping import ExternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser, _SDO_TYPING
from misp_stix_converter.stix2misp.exceptions import (UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError, UnknownPatternTypeError)
from pymisp import MISPObject
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
            return self.mapping.pattern_mapping[observable_types]
        except KeyError:
            raise UnknownPatternMappingError(observable_types)

    def _parse_indicator(self, indicator_ref: str):
        """
        Indicators parsing function. Gets the parsing function depending on the
        types found within the pattern, and simply calls the parsing function that
        will simply parse the pattern, create the appropriate MISP data structure
        and add it to the associated MISP event.

        :param indicator_ref: The indicator id used to find the corresponding
            indicator object
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

    def _parse_location(self, location_ref: str):
        """
        STIX 2.1 Location object parsing function. A geolocation MISP object is
        created and the different STIX fields are converted into the appropriate
        object attributes (Common with the parent parsing class).

        :param location_ref: The Location object id used to find the corresponding
            STIX object
        """
        location = self._get_stix2_object(location_ref)
        misp_object = self._parse_location_object(location)
        self._add_misp_object(misp_object)

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

    def _parse_vulnerability(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
        """
        Vulnerabilty parsing function.
        If the vulnerability name is a knwown Galaxy Cluster name, we store the
        associated tag names that will be used afterwards to populate the Galaxies
        list within the appropriate MISP data structure.
        Otherwise, the vulnerability is parsed and depending on the converted
        attributes, the result is either a MISP attribute or a MISP object.

        :param vulnerability: A STIX 2.0 or 2.1 Vulnerability object to parse
        """
        name = vulnerability.name
        if name in self.synonyms_mapping:
            self._galaxy[vulnerability.id.split('--')[1]] = {
                'tag_names': self.synonyms_mapping[name],
                'used': False
            }
        else:
            attributes = self._get_attributes_from_observable(vulnerability, 'vulnerability_mapping')
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
                        feature = 'vulnerability_attribute' if external_id == name else 'references_attribute'
                        attribute.update(getattr(self._mapping, feature))
                        attributes.append(attribute)
            self._handle_import_case(vulnerability, attributes, 'vulnerability')

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
        if any(keyword in pattern for keyword in self._mapping.pattern_forbiden_relations):
            return True
        if all(keyword in pattern for keyword in (' AND ', ' OR ')):
            return True
        return False
