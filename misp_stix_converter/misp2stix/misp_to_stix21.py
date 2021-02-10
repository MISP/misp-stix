#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from stix2.v21.bundle import Bundle
from stix2.v21.common import MarkingDefinition
from stix2.v21.observables import AutonomousSystem, DomainName, IPv4Address, IPv6Address
from stix2.v21.sdo import Grouping, Identity, Indicator, ObservedData, Report
from typing import Union

_OBSERVABLE_OBJECT_TYPES = Union[
    AutonomousSystem
]


class MISPtoSTIX21Parser(MISPtoSTIX2Parser):
    def __init__(self):
        super().__init__()
        self._version = '2.1'

    def _handle_unpublished_report(self, report_args: dict) -> Grouping:
        report_args.update(
            {
                'id': f"grouping--{self._misp_event['uuid']}",
                'type': 'grouping',
                'context': 'suspicious-activity'
            }
        )
        return Grouping(**report_args)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _parse_autonomous_system_attribute_observable(self, attribute: dict):
        AS_object = AutonomousSystem(
            id=f"autonomous-system--{attribute['uuid']}",
            number=self._parse_AS_value(attribute['value'])
        )
        self._create_observed_data(attribute, [AS_object])

    def _parse_domain_attribute_observable(self, attribute: dict):
        domain_object = DomainName(
            id=f"domain-name--{attribute['uuid']}",
            value=attribute['value']
        )
        self._create_observed_data(attribute, [domain_object])

    def _parse_domain_ip_attribute_observable(self, attribute: dict):
        domain, ip = attribute['value'].split('|')
        address_type = self._get_address_type(ip)
        address_id = f"{address_type._type}--{attribute['uuid']}"
        address_object = address_type(
            id=address_id,
            value=ip
        )
        domain_object = DomainName(
            id=f"domain-name--{attribute['uuid']}",
            value=domain,
            resolves_to_refs=[address_id]
        )
        self._create_observed_data(
            attribute,
            [
                domain_object,
                address_object
            ]
        )

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_bundle(self) -> Bundle:
        return Bundle(self._objects)

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
    def _create_grouping(grouping_args):
        return Grouping(**grouping_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        indicator_args.update(
            {
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern_version": "2.1",
            }
        )
        return Indicator(**indicator_args)

    def _create_marking(self, marking: str) -> Union[str, None]:
        if marking in stix2_mapping.tlp_markings_v21:
            marking_definition = deepcopy(stix2_mapping.tlp_markings_v21[marking])
            self._markings[marking] = marking_definition
            return marking_definition.id
        marking_args = self._create_marking_definition_args(marking)
        try:
            self._markings[marking] = MarkingDefinition(**marking_args)
        except (TLPMarkingDefinitionError, ValueError):
            return
        return marking_args['id']

    def _create_observed_data(self, attribute: dict, observables: list):
        observable_args = self._create_observable_args(attribute)
        observable_args['object_refs'] = [observable.id for observable in observables]
        observed_data = ObservedData(**observable_args)
        self._append_SDO(observed_data)
        for observable in observables:
            self._append_SDO(observable)

    @staticmethod
    def _create_report(report_args):
        return Report(**report_args)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _get_address_type(address):
        if ':' in address:
            return IPv6Address
        return IPv4Address
