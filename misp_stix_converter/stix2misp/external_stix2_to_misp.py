#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from misp_stix_converter.stix2misp.exceptions import (UnknownParsingFunctionError,
    UnknownObservableMappingError, UnknownPatternMappingError, UnknownPatternTypeError)
from .external_stix2_mapping import ExternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser
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

    def _handle_observable_objects_mapping(self, observable_objects: dict) -> str:
        observable_types = self._extract_types_from_observable_objects(observable_objects)
        try:
            feature = self._mapping.observable_mapping[observable_types]
        except KeyError:
            raise UnknownObservableMappingError(observable_types)
        return f'{feature}_objects'

    def _handle_observable_refs_mapping(self, observable_refs: list) -> str:
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
        if isinstance(indicator, Indicator_v21):
            try:
                return self._mapping.pattern_type_mapping[indicator.pattern_type]
            except KeyError:
                raise UnknownPatternTypeError(indicator.pattern_type)
        observable_types = self._extract_types_from_pattern(indicator.pattern)
        try:
            return self.mapping.pattern_mapping[observable_types]
        except KeyError:
            raise UnknownPatternMappingError(observable_types)

    def _parse_indicator(self, indicator_ref: str):
        """
        """
        indicator = self._get_stix_object(indicator_ref)
        try:
            feature = self._handle_pattern_mapping(indicator)
        except UnknownPatternMappingError as error:
            self._unknown_pattern_mapping_error(indicator.id, error)
            return
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

    def _parse_observed_data_v20(self, observed_data: ObservedData_v20):
        """
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
        """
        if hasattr(observed_data, 'object_refs'):
            observable_types = self._extract_types_from_observable_refs(observed_data.object_refs)
            try:
                feature = self._mapping.observable_mapping[observable_types]
            except KeyError:
                self._unknown_observable_mapping_error(observed_data.id)

        observable_types = self._extract_types_from_observable(observed_data)
        try:
            feature = self._mapping.observable_mapping[observable_types]
        except KeyError:
            self.

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _extract_types_from_observable_objects(observable_objects: dict) -> tuple:
        return sorted(tuple({observable.type for observable in observable_objects.values()}))

    def _extract_types_from_observable_refs(self, observable_refs: list) -> tuple:
        return sorted(tuple({self._observable[object_ref].type for object_ref in observable_refs}))