#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .stix1_mapping import InternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.abstract import resources_path
from pymisp.api import describe_types
from stix.exploit_target import Vulnerability, Weakness
from stix.indicator import Indicator, Observable
from stix.ttp import TTP
from stix.ttp.attack_pattern import AttackPattern
from typing import Optional

_MISP_categories = describe_types.get('categories')
_MISP_objects_path = resources_path / 'objects'


class InternalSTIX1toMISPParser(STIX1toMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = InternalSTIX1toMISPMapping
        self.__dates = set()
        self.__timestamps = set()
        self.__titles = set()

    def parse_stix_package(self, **kwargs):
        self._set_parameters(**kwargs)
        self._set_misp_event(MISPEvent())
        for item in self.stix_package.related_packages.related_package:
            package = item.item
            self._event = package.incidents[0]
            object_references = []
            for coa_taken in self._event.coa_taken:
                self._parse_course_of_action(coa_taken.course_of_action)
            if self._event.attributed_threat_actors:
                object_references.extend(
                    threat_actor.item.idref for threat_actor
                    in self._event.attributed_threat_actors.threat_actor
                )
            if self._event.leveraged_ttps and self._event.leveraged_ttps.ttp:
                object_references.extend(
                    ttp.item.idref for ttp in self._event.leveraged_ttps.ttp
                )
            object_references = tuple(
                '-'.join(part for part in reference.split('-')[-5:])
                for reference in object_references if reference is not None
            )
            if self._event.timestamp:
                stix_date = self._event.timestamp
                try:
                    self.dates.add(stix_date.date())
                except AttributeError:
                    self.dates.add(stix_date)
                self.timestamps.add(self._timestamp_from_date(stix_date))
            self.titles.add(self._get_event_info())
            if self._event.related_indicators:
                for indicator in self._event.related_indicators.indicator:
                    self._parse_indicator(indicator)
            if self._event.related_observables:
                for observable in self._event.related_observables.observable:
                    self._parse_observable(observable)
            if self._event.history:
                for entry in self.event.history.history_items:
                    journal_entry = entry.journal_entry.value
                    try:
                        entry_type, entry_value = journal_entry.split(': ')
                        if entry_type == "MISP Tag":
                            self.misp_event.add_tag(entry_value)
                        elif entry_type.startswith('attribute['):
                            _, category, attribute_type = entry_type.split('[')
                            self.misp_event.add_attribute(
                                **{
                                    'type': attribute_type[:-1],
                                    'category': category[:-1],
                                    'value': entry_value
                                }
                            )
                        elif entry_type == "Event Threat Level":
                            threat_level = self._mapping.threat_level_mapping(
                                entry_value
                            )
                            if threat_level is not None:
                                self.misp_event.threat_level_id = threat_level
                    except ValueError:
                        continue
            if self._event.information_source and self._event.information_source.references:
                for reference in self._event.information_source.references:
                    self.misp_event.add_attribute(**{'type': 'link', 'value': reference})
            if package.courses_of_action:
                for course_of_action in package.courses_of_action:
                    self.galaxies.update(
                        self._parse_galaxy(course_of_action, 'title', 'course-of-action')
                    )
            if package.threat_actors:
                for threat_actor in package.threat_actors:
                    self.galaxies.update(
                        self._parse_galaxy(threat_actor, 'title', 'threat-actor')
                    )
            if package.ttps:
                for ttp in package.ttps.ttp:
                    ttp_id = '-'.join((part for part in ttp.id_.split('-')[-5:]))
                    if ttp_id not in object_references:
                        self._parse_ttp(ttp)
                        continue
                    if ttp.behavior:
                        if ttp.behavior.attack_patterns:
                            for attack_pattern in ttp.behavior.attack_patterns:
                                self._parse_attack_pattern_object(attack_pattern, ttp_id)
                        continue
                    if ttp.exploit_targets and ttp.exploit_targets.exploit_target:
                        for exploit_target in ttp.exploit_targets.exploit_target:
                            if exploit_target.item.vulnerabilities:
                                for vulnerability in exploit_target.item.vulnerabilities:
                                    self._parse_vulnerability_object(vulnerability, ttp_id)
                            if exploit_target.item.weaknesses:
                                for weakness in exploit_target.item.weaknesses:
                                    self._parse_weakness_object(weakness, ttp_id)
                    # if ttp.handling:
                    #     self.parse_tlp_marking(ttp.handling)
        self._set_distribution()
        self.misp_event.info = ' - '.join(self.titles)
        self.misp_event.date = max(self.dates)
        self.misp_event.timestamp = max(self.timestamps)

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def dates(self) -> set:
        return self.__dates

    @property
    def timestamps(self) -> set:
        return self.__timestamps

    @property
    def titles(self) -> set:
        return self.__titles

    ############################################################################
    #                       STIX OBJECTS PARSING METHODS                       #
    ############################################################################

    def _parse_attack_pattern_object(self, attack_pattern: AttackPattern, ttp_id: str):
        attributes = []
        for key, relation in self._mapping.attack_pattern_object_mapping().items():
            value = getattr(attack_pattern, key)
            if value:
                attributes.append(
                    (relation, value if isinstance(value, str) else value.value)
                )
        if attributes:
            attack_pattern_object = MISPObject('attack-pattern')
            attack_pattern_object.uuid = ttp_id
            for attribute in attributes:
                attack_pattern_object.add_attribute(*attribute)
            self.misp_event.add_object(attack_pattern_object)

    # Parse indicators of a STIX document coming from our exporter
    def _parse_indicator(self, indicator: Indicator):
        # define is an indicator will be imported as attribute or object
        if indicator.relationship in _MISP_categories:
            self._parse_misp_attribute_indicator(indicator)
        else:
            self._parse_misp_object_indicator(indicator)

    def _parse_observable(self, observable: Observable):
        if observable.relationship in _MISP_categories:
            self.parse_misp_attribute_observable(observable)
        else:
            self.parse_misp_object_observable(observable)

    def _parse_ttp(self, ttp: TTP):
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    self.galaxies.update(self._parse_galaxy(attack_pattern, 'title', 'misp-attack-pattern'))
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    if not malware_instance._XSI_TYPE or 'stix-maec' not in malware_instance._XSI_TYPE:
                        self.galaxies.update(self._parse_galaxy(malware_instance, 'title', 'ransomware'))
        elif ttp.exploit_targets:
            if ttp.exploit_targets.exploit_target:
                for exploit_target in ttp.exploit_targets.exploit_target:
                    if exploit_target.item.vulnerabilities:
                        for vulnerability in exploit_target.item.vulnerabilities:
                            self.galaxies.update(
                                self._parse_galaxy(vulnerability, 'title', 'branded-vulnerability')
                            )
        elif ttp.resources:
            if ttp.resources.tools:
                for tool in ttp.resources.tools:
                    self.galaxies.update(self._parse_galaxy(tool, 'name', 'tool'))

    def _parse_vulnerability_object(self, vulnerability: Vulnerability, ttp_id: str):
        attributes = []
        for key, mapping in self._mapping.vulnerability_object_mapping().items():
            value = getattr(vulnerability, key)
            if value:
                attribute_type, relation = mapping
                attributes.append(
                    {
                        'type': attribute_type, 'object_relation': relation,
                        'value': value if isinstance(value, str) else value.value
                    }
                )
        if attributes:
            if len(attributes) == 1 and attributes[0]['object_relation'] == 'id':
                attributes = attributes[0]
                attributes['uuid'] = ttp_id
                self.misp_event.add_attribute(**attributes)
            else:
                vulnerability_object = MISPObject('vulnerability')
                vulnerability_object.uuid = ttp_id
                for attribute in attributes:
                    vulnerability_object.add_attribute(*attribute)
                self.misp_event.add_object(vulnerability_object)

    def _parse_weakness_object(self, weakness: Weakness, ttp_id: str):
        attributes = []
        for key, relation in self._mapping.weakness_object_mapping().items():
            value = getattr(weakness, key)
            if value:
                attributes.append(
                    (relation, value if isinstance(value, str) else value.value)
                )
        if attributes:
            weakness_object = MISPObject('weakness')
            weakness_object.uuid = ttp_id
            for attribute in attributes:
                weakness_object.add_attribute(*attribute)
            self.misp_event.add_object(weakness_object)

    ############################################################################
    #                           MISP PARSING METHODS                           #
    ############################################################################

    # Parse STIX objects that we know will give MISP attributes
    def _parse_misp_attribute_indicator(self, indicator: Indicator):
        item = indicator.item
        if item.observable:
            misp_attribute = {
                'to_ids': True, 'category': str(indicator.relationship),
                'timestamp': self._timestamp_from_date(item.timestamp)
            }
            misp_attribute.update(self._sanitise_attribute_uuid(indicator.id_))
            observable = item.observable
            self._parse_misp_attribute(observable, misp_attribute, indicator.id_, to_ids=True)

    def _parse_misp_attribute_observable(self, observable):
        if observable.item:
            misp_attribute = {
                'to_ids': False, 'category': str(observable.relationship)
            }
            misp_attribute.update(
                self._sanitise_attribute_uuid(observable.item.id_)
            )
            self._parse_misp_attribute(observable.item, misp_attribute, observable.id_)

    def _parse_misp_attribute(
            self, observable: Observable, misp_attribute: dict,
            stix_object_id: str, to_ids: Optional[bool] = False):
        if getattr(observable.object_, 'properties', None) is not None:
            properties = observable.object_.properties
            try:
                attribute_type, attribute_value, compl_data = self._handle_attribute_type(
                    properties, title=observable.title
                )
                if isinstance(attribute_value, (str, int)):
                    self._handle_attribute_case(attribute_type, attribute_value, compl_data, misp_attribute)
                else:
                    self._handle_object_case(attribute_type, attribute_value, compl_data, to_ids=to_ids)
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, stix_object_id)
        elif getattr(observable.observable_composition, 'observables', None) is not None:
            attribute_dict = {}
            for observables in observable.observable_composition.observables:
                properties = observables.object_.properties
                try:
                    attribute_type, attribute_value, _ = self._handle_attribute_type(
                        properties, observable_id=observable.id_
                    )
                    attribute_dict[attribute_type] = attribute_value
                except StixObjectTypeError as xsi_type:
                    self._stix_object_type_error(xsi_type, stix_object_id)
            if attribute_dict:
                attribute_type, attribute_value = self._composite_type(attribute_dict)
                self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attribute)

    # Parse STIX object that we know will give MISP objects
    def _parse_misp_object_indicator(self, indicator: Indicator):
        name = self._define_name(indicator.item.observable, indicator.relationship)
        if name == 'passive-dns' and str(indicator.relationship) != "misc":
            self._add_error(
                f'Unable to parse the Indicator object with id {indicator.id_}'
            )
        else:
            self._fill_misp_object(indicator.item, name, to_ids=True)

    def _parse_misp_object_observable(self, observable: Observable):
        name = self._define_name(observable.item, observable.relationship)
        try:
            self._fill_misp_object(observable, name)
        except Exception:
            self._add_error(
                'Unable to parse the Observable '
                f'object with id {observable.id_}'
            )

    ############################################################################
    #                       MISP OBJECTS PARSING METHODS                       #
    ############################################################################

    # Create a MISP object, its attributes, and add it in the MISP event
    def _fill_misp_object(self, item, name, to_ids=False):
        composition = any(
            (
                (
                    hasattr(item, 'observable') and
                    hasattr(item.observable, 'observable_composition') and
                    item.observable.observable_composition
                ),
                (
                    hasattr(item, 'observable_composition') and
                    item.observable_composition
                )
            )
        )
        if composition:
            misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
            self._sanitise_object_uuid(misp_object, item.id_)
            if to_ids:
                observables = item.observable.observable_composition.observables
                misp_object.timestamp = self._get_imestamp_from_date(item.timestamp)
            else:
                observables = item.observable_composition.observables
            args = (misp_object, observables, to_ids)
            self._handle_file_composition(*args) if name == 'file' else self._handle_composition(*args)
            self.misp_event.add_object(**misp_object)
        else:
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            self._parse_observable_object(properties, to_ids, self._sanitise_uuid(item.id_))

    def _handle_composition(self, misp_object, observables, to_ids):
        for observable in observables:
            properties = observable.object_.properties
            try:
                attribute = self._handle_attribute_type(properties)
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                continue
            misp_attribute = MISPAttribute()
            misp_attribute.type, misp_attribute.value, misp_attribute.object_relation = attribute
            if 'Port' in observable.id_:
                misp_attribute.object_relation = '-'.join(
                    (
                        observable.id_.split('-')[0].split(':')[1][:3],
                        misp_attribute.object_relation
                    )
                )
            misp_attribute.to_ids = to_ids
            misp_object.add_attribute(**misp_attribute)
        return misp_object

    def  _handle_file_composition(self, misp_object, observables, to_ids):
        for observable in observables:
            try:
                attribute_type, attribute_value, compl_data = self._handle_attribute_type(
                    observable.object_.properties, title=observable.title
                )
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                continue
            if isinstance(attribute_value, str):
                misp_object.add_attribute(
                    **{
                        'type': attribute_type, 'value': attribute_value,
                        'object_relation': attribute_type, 'to_ids': to_ids,
                        'data': compl_data
                    }
                )
            else:
                for attribute in attribute_value:
                    attribute['to_ids'] = to_ids
                    misp_object.add_attribute(**attribute)
        return misp_object

    # Create a MISP attribute and add it in its MISP object
    def _parse_observable_object(self, properties, to_ids, uuid):
        attribute_type, attribute_value, compl_data = self._handle_attribute_type(properties)
        if isinstance(attribute_value, (str, int)):
            attribute = {'to_ids': to_ids, 'uuid': uuid}
            self._handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
        else:
            self._handle_object_case(attribute_type, attribute_value, compl_data, to_ids=to_ids, object_uuid=uuid)

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    # Return type & value of a composite attribute in MISP
    @staticmethod
    def _composite_type(attributes: dict):
        if "port" in attributes:
            if "ip-src" in attributes:
                return "ip-src|port", f"{attributes['ip-src']}|{attributes['port']}"
            elif "ip-dst" in attributes:
                return "ip-dst|port", f"{attributes['ip-dst']}|{attributes['port']}"
            elif "hostname" in attributes:
                return "hostname|port", f"{attributes['hostname']}|{attributes['port']}"
        elif "domain" in attributes:
            if "ip-src" in attributes:
                ip_value = attributes["ip-src"]
            elif "ip-dst" in attributes:
                ip_value = attributes["ip-dst"]
            return "domain|ip", f"{attributes['domain']}|{ip_value}"

    def _define_name(self, observable: Observable, relationship):
        observable_id = observable.id_
        if relationship == "file":
            return "registry-key" if "WinRegistryKey" in observable_id else "file"
        if "Custom" in observable_id:
            return observable_id.split("Custom")[0].split(":")[1]
        if relationship == "network" and "ObservableComposition" in observable_id:
            return observable_id.split("_")[0].split(":")[1]
        return self._mapping.cybox_to_misp_object()[observable_id.split('-')[0].split(':')[1]]

    def _get_event_info(self):
        if hasattr(self._event, 'title'):
            return self._event.title
        if hasattr(getattr(self._event, 'stix_header', None), 'title'):
            return self.event.stix_header.title
        return f"Imported from STIX {self.stix_version} Package generated with MISP"
