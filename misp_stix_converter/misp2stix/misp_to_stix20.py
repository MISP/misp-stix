#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from stix2.v20.bundle import Bundle
from stix2.v20.common import MarkingDefinition
from stix2.v20.observables import AutonomousSystem
from stix2.v20.sdo import Identity, Indicator, ObservedData, Report
from typing import Union


class MISPtoSTIX20Parser(MISPtoSTIX2Parser):
    def __init__(self):
        super().__init__()
        self._version = '2.0'

    def _handle_unpublished_report(self, report_args: dict) -> Report:
        report_args.update(
            {
                'id': f"report--{self._misp_event['uuid']}",
                'type': 'report',
                'published': report_args['modified']
            }
        )
        return Report(**report_args)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _parse_autonomous_system_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': AutonomousSystem(number=self._parse_AS_value(attribute['value']))
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_domain_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': DomainName(value=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_bundle(self) -> Bundle:
        return Bundle(self._objects)

    @staticmethod
    def _create_grouping(grouping_args):
        return Grouping(**grouping_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        identity_args = {
            'type': 'identity',
            'id': self._identity_id,
            'name': orgname,
            'identity_class': 'organization',
            'interoperability': True
        }
        return Identity(**identity_args)

    @staticmethod
    def _create_indicator(self, indicator_args: dict) -> Indicator:
        return Indicator(**indicator_args)

    def _create_marking(self, marking: str) -> Union[str, None]:
        if marking in stix2_mapping.tlp_markings_v20:
            marking_definition = deepcopy(stix2_mapping.tlp_markings_v20[marking])
            self._markings[marking] = marking_definition
            return marking_definition.id
        marking_args = self._create_marking_definition_args(marking)
        try:
            self._markings[marking] = MarkingDefinition(**marking_args)
        except (TLPMarkingDefinitionError, ValueError):
            return
        return marking_args['id']

    def _create_observed_data(self, attribute: dict, observable: dict):
        observable_args = self._create_observable_args(attribute)
        observable_args['objects'] = observable
        observable = ObservedData(**observable_args)
        self._append_SDO(observable)

    @staticmethod
    def _create_report(report_args):
        return Report(**report_args)
