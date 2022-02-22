#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from misp_stix_converter.stix2misp.exceptions import (UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError, UnknownPatternTypeError)
from .external_stix2_mapping import ExternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser
from pymisp import MISPObject
from stix2.v20.sdo import Indicator as Indicator_v20, ObservedData as ObservedData_v20
from stix2.v21.sdo import Indicator as Indicator_v21, ObservedData as ObservedData_v21
from typing import Union


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, single_event: bool):
        super().__init__(single_event)
        self._mapping = ExternalSTIX2Mapping()

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

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
                return self._mapping.pattern_type_mapping[indicator.pattern_type]
            except KeyError:
                raise UnknownPatternTypeError(indicator.pattern_type)
        if any(keyword in indicator.pattern for keyword in self._mapping.pattern_forbiden_relations):
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

        :param indicator_ref: An indicator id used to find the corresponding
            indicator object
        """
        indicator = self._get_stix_object(indicator_ref)
        try:
            feature = self._handle_pattern_mapping(indicator)
        except UnknownPatternMappingError as error:
            self._unknown_pattern_mapping_warning(indicator.id, error)
            feature = '_create_stix_pattern_object'
        except UnknownPatternTypeError as error:
            self._unknown_pattern_type_warning(indicator.id, error)
            feature = '_create_stix_pattern_object'
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(indicator)
        except Exception as exception:
            self._indicator_error(indicator.id, exception)

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

    ################################################################################
    #                     OBSERVABLE OBJECTS PARSING FUNCTIONS                     #
    ################################################################################

    ################################################################################
    #                          PATTERNS PARSING FUNCTIONS                          #
    ################################################################################

    def _create_stix_pattern_object(self, indicator):
        misp_object = MISPObject('stix2-pattern')
        misp_object.uuid = indicator.id.split('--')[-1]
        misp_object.update(self._parse_timeline(indicator))
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
        self._add_object(misp_object)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _extract_types_from_observable_objects(observable_objects: dict) -> tuple:
        return sorted(tuple({observable.type for observable in observable_objects.values()}))

    def _extract_types_from_observable_refs(self, observable_refs: list) -> tuple:
        return sorted(tuple({self._observable[object_ref].type for object_ref in observable_refs}))