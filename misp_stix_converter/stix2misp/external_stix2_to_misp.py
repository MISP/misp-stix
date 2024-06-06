#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import UnknownParsingFunctionError, UnknownStixObjectTypeError
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .converters import (
    ExternalSTIX2AttackPatternConverter, ExternalSTIX2CampaignConverter,
    ExternalSTIX2CourseOfActionConverter, ExternalSTIX2IdentityConverter,
    ExternalSTIX2IndicatorConverter, ExternalSTIX2IntrusionSetConverter,
    ExternalSTIX2LocationConverter, ExternalSTIX2MalwareAnalysisConverter,
    ExternalSTIX2MalwareConverter, ExternalSTIX2ObservedDataConverter,
    ExternalSTIX2ThreatActorConverter, ExternalSTIX2ToolConverter,
    ExternalSTIX2VulnerabilityConverter, STIX2ObservableObjectConverter)
from .stix2_to_misp import STIX2toMISPParser, _OBSERVABLE_TYPING
from collections import defaultdict
from typing import Optional, Union

MISP_org_uuid = '55f6ea65-aa10-4c5a-bf01-4f84950d210f'



class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, distribution: Optional[int] = 0,
                 sharing_group_id: Optional[int] = None,
                 galaxies_as_tags: Optional[bool] = False,
                 organisation_uuid: Optional[str] = MISP_org_uuid,
                 cluster_distribution: Optional[int] = 0,
                 cluster_sharing_group_id: Optional[int] = None):
        super().__init__(distribution, sharing_group_id, galaxies_as_tags)
        self._set_cluster_distribution(
            self._sanitise_distribution(cluster_distribution),
            self._sanitise_sharing_group_id(cluster_sharing_group_id)
        )
        self.__organisation_uuid = organisation_uuid
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
        self._observed_data_parser: ExternalSTIX2ObservedDataConverter
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

    @property
    def organisation_uuid(self) -> str:
        return self.__organisation_uuid

    def _set_attack_pattern_parser(self):
        self._attack_pattern_parser = ExternalSTIX2AttackPatternConverter(self)

    def _set_campaign_parser(self):
        self._campaign_parser = ExternalSTIX2CampaignConverter(self)

    def _set_cluster_distribution(
            self, distribution: int, sharing_group_id: Union[int, None]):
        cluster_distribution = {'distribution': distribution}
        if distribution == 4 and sharing_group_id is not None:
            cluster_distribution['sharing_group_id'] = sharing_group_id
        self.__cluster_distribution = cluster_distribution

    def _set_course_of_action_parser(self):
        self._course_of_action_parser = ExternalSTIX2CourseOfActionConverter(self)

    def _set_identity_parser(self):
        self._identity_parser = ExternalSTIX2IdentityConverter(self)

    def _set_indicator_parser(self):
        self._indicator_parser = ExternalSTIX2IndicatorConverter(self)

    def _set_intrusion_set_parser(self):
        self._intrusion_set_parser = ExternalSTIX2IntrusionSetConverter(self)

    def _set_location_parser(self):
        self._location_parser = ExternalSTIX2LocationConverter(self)

    def _set_malware_analysis_parser(self):
        self._malware_analysis_parser = ExternalSTIX2MalwareAnalysisConverter(self)

    def _set_malware_parser(self):
        self._malware_parser = ExternalSTIX2MalwareConverter(self)

    def _set_observable_object_parser(self):
        self._observable_object_parser = STIX2ObservableObjectConverter(self)

    def _set_observed_data_parser(self):
        self._observed_data_parser = ExternalSTIX2ObservedDataConverter(self)

    def _set_threat_actor_parser(self):
        self._threat_actor_parser = ExternalSTIX2ThreatActorConverter(self)

    def _set_tool_parser(self):
        self._tool_parser = ExternalSTIX2ToolConverter(self)

    def _set_vulnerability_parser(self):
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
