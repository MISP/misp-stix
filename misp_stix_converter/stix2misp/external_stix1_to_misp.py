#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .importparser import ExternalSTIXtoMISPParser
from .stix1_mapping import ExternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from collections import defaultdict
from cybox.core import Observable, Observables
from pymisp.abstract import misp_objects_path
from pymisp import MISPAttribute, MISPEvent, MISPObject
from stix.data_marking import MarkingSpecification
from stix.extensions.marking.ais import AISMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from stix.ttp import TTP
from typing import Optional, Union

class ExternalSTIX1toMISPParser(STIX1toMISPParser, ExternalSTIXtoMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = ExternalSTIX1toMISPMapping
        self.__dns_objects = defaultdict(dict)
        self.__dns_ips = []

    def parse_stix_package(self, cluster_distribution: Optional[int] = 0,
                           cluster_sharing_group_id: Optional[int] = None,
                           organisation_uuid: Optional[str] = None, **kwargs):
        self._set_parameters(**kwargs)
        self._set_single_event(True)
        self._set_cluster_distribution(
            cluster_distribution, cluster_sharing_group_id
        )
        self._set_organisation_uuid(organisation_uuid)
        self._set_misp_event(MISPEvent())
        if self.stix_package.timestamp:
            stix_date = self.stix_package.timestamp
            try:
                self.misp_event.date = stix_date.date()
            except AttributeError:
                self.misp_event.date = stix_date
            self.misp_event.timestamp = self._timestamp_from_date(stix_date)
        self.misp_event.info = self._get_event_info()
        header = self.stix_package.stix_header
        if getattr(getattr(header, 'description', None), 'value', None):
            self.misp_event.add_attribute(
                **{
                    'type': 'text', 'value': header.description.value,
                    'comment': 'STIX Header Description'
                }
            )
        if getattr(header, 'handling', None):
            for handling in header.handling:
                for tag in self._parse_marking(handling):
                    self.misp_event.add_tag(tag)
        if self.stix_package.indicators:
            for indicator in self.stix_package.indicators:
                if indicator.related_indicators:
                    for related_indicator in indicator.related_indicators:
                        self._parse_indicator(related_indicator)
                else:
                    self._parse_indicator(indicator)
        if self.stix_package.observables:
            self._parse_observables()
        if self.stix_package.ttps:
            for ttp in self.stix_package.ttps.ttp:
                self._parse_ttp(ttp)
        if self.stix_package.courses_of_action:
            for course_of_action in self.stix_package.courses_of_action:
                self._parse_course_of_action(course_of_action)
        if self.stix_package.threat_actors:
            for threat_actor in self.stix_package.threat_actors:
                self._parse_threat_actor(threat_actor)
        if self.dns_objects:
            for domain in self.dns_objects['domain'].values():
                domain_attribute = domain['data']
                ip_reference = domain['related']
                if ip_reference in self.dns_objects['ip']:
                    misp_object = MISPObject(
                        'passive-dns', misp_objects_path_custom=misp_objects_path
                    )
                    domain_attribute['object_relation'] = "rrname"
                    misp_object.add_attribute(**domain_attribute)
                    ip_address = self.dns_objects['ip'][ip_reference]['value']
                    misp_object.add_attribute(
                        **{
                            "type": "text", "object_relation": "rdata",
                            "value": ip_address
                        }
                    )
                    misp_object.add_attribute(
                        **{
                            'type': 'text', 'object_relation': 'rrtype',
                            'value': "AAAA" if ":" in ip_address else "A"
                        }
                    )
                    self.misp_event.add_object(misp_object)
                else:
                    self.misp_event.add_attribute(**domain_attribute)
            for ip, ip_attribute in self.dns_objects['ip'].items():
                if ip not in self.dns_ips:
                    self.misp_event.add_attribute(**ip_attribute)

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def dns_ips(self) -> list:
        return self.__dns_ips

    @property
    def dns_objects(self) -> dict:
        return self.__dns_objects

    ############################################################################
    #                       STIX OBJECTS PARSING METHODS                       #
    ############################################################################

    def _parse_attributes_from_ttp(self, ttp: TTP, galaxies: set):
        attributes = []
        if ttp.resources and getattr(ttp.resources, 'infrastructure', None).observable_characterization:
            observables = ttp.resources.infrastructure.observable_characterization
            if observables.observables:
                for observable in observables.observables:
                    if not self._has_properties(observable):
                        continue
                    properties = observable.object_.properties
                    try:
                        attribute_type, attribute_value, _ = self._handle_attribute_type(properties)
                    except StixObjectTypeError as xsi_type:
                        self._stix_object_type_error(xsi_type, ttp.id_)
                        continue
                    if isinstance(attribute_value, list):
                        attributes.extend(
                            {'type': attribute_type, 'value': value, 'to_ids': False}
                            for value in attribute_value
                        )
                    else:
                        attributes.append(
                            {
                                'type': attribute_type,
                                'value': attribute_value,
                                'to_ids': False
                            }
                        )
        if ttp.exploit_targets and ttp.exploit_targets.exploit_target:
            for exploit_target in ttp.exploit_targets.exploit_target:
                if exploit_target.item.vulnerabilities:
                    for vulnerability in exploit_target.item.vulnerabilities:
                        if vulnerability.cve_id:
                            attributes.append(
                                {
                                    'type': 'vulnerability',
                                    'value': vulnerability.cve_id
                                }
                            )
                        elif vulnerability.title:
                            title = vulnerability.title
                            if title in self.synonyms_mapping:
                                galaxies.update(self.synonyms_mapping[title])
                            else:
                                galaxies.add(f'misp-galaxy:branded-vulnerability="{title}"')
        if len(attributes) == 1:
            attributes[0].update(self._sanitise_attribute_uuid(ttp.id_))
        return attributes

    def _parse_description(self, stix_object: Union[Indicator, Observable]):
        if stix_object.description:
            misp_attribute = {
                'type': 'text', 'value': stix_object.description.value
            }
            if stix_object.timestamp:
                misp_attribute['timestamp'] = self._timestamp_from_date(
                    stix_object.timestamp
                )
            self.misp_event.add_attribute(**misp_attribute)

    def _parse_galaxies_from_ttp(self, ttp: TTP):
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    yield from self._parse_galaxy(attack_pattern, 'title', 'misp-attack-pattern')
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    yield from self._parse_galaxy(malware_instance, 'title', 'ransomware')
        if ttp.resources and ttp.resources.tools:
            for tool in ttp.resources.tools:
                yield from self._parse_galaxy(tool, 'name', 'tool')

    def _parse_indicator(self, indicator: Indicator):
        if hasattr(indicator, 'observable') and indicator.observable:
            observable = indicator.observable
            if self._has_properties(observable):
                properties = observable.object_.properties
                uuid = self._sanitise_uuid(observable.object_.id_)
                try:
                    attribute_type, attribute_value, compl_data = self._handle_attribute_type(properties)
                except StixObjectTypeError as xsi_type:
                    self._stix_object_type_error(xsi_type, indicator.id_)
                    return
                if isinstance(attribute_value, (str, int)):
                    if observable.object_.related_objects:
                        related_objects = observable.object_.related_objects
                        resolving = (
                            attribute_type == "url" and len(related_objects) == 1 and
                            related_objects[0].relationship.value == "Resolved_To"
                        )
                        if resolving:
                            related_ip = self._sanitise_uuid(related_objects[0].idref)
                            self.dns_objects['domain'][uuid] = {
                                "related": related_ip, "data": {
                                    "type": "text", "value": attribute_value
                                }
                            }
                            if related_ip not in self.dns_ips:
                                self.dns_ips.append(related_ip)
                            return
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': True, 'uuid': uuid}
                    if indicator.timestamp:
                        attribute['timestamp'] = self._timestamp_from_date(indicator.timestamp)
                    if hasattr(observable, 'handling') and observable.handling:
                        attribute['Tag'] = []
                        for handling in observable.handling:
                            attribute['Tag'].extend(self._parse_marking(handling))
                    if attribute_type in ('ip-src', 'ip-dst'):
                        attribute.update(
                            {'type': attribute_type, 'value': attribute_value}
                        )
                        self.dns_objects['ip'][uuid] = attribute
                        return
                    self._handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                elif attribute_value:
                    if all(isinstance(value, dict) for value in attribute_value):
                        # it is a list of attributes, so we build an object
                        test_mechanisms = []
                        if hasattr(indicator, 'test_mechanisms') and indicator.test_mechanisms:
                            for test_mechanism in indicator.test_mechanisms:
                                attribute_type = self._mapping.test_mechanisms_mapping(test_mechanism._XSI_TYPE)
                                if attribute_type is None:
                                    self._add_error(
                                        'Unknown Test Mechanism type'
                                        f': {test_mechanism._XSI_TYPE}'
                                    )
                                    continue
                                if test_mechanism.rule.value is None:
                                    continue
                                self.misp_event.add_attribute(
                                    **{
                                        'type': attribute_type,
                                        'value': test_mechanism.rule.value
                                    }
                                )
                                test_mechanisms.append(attribute.uuid)
                        self._handle_object_case(
                            attribute_type, attribute_value, compl_data,
                            to_ids=True, object_uuid=uuid,
                            test_mechanisms=test_mechanisms
                        )
                    else:
                        # it is a list of attribute values, so we add single attributes
                        for value in attribute_value:
                            self.misp_event.add_attribute(**{'type': attribute_type, 'value': value, 'to_ids': True})
            elif hasattr(observable, 'observable_composition') and observable.observable_composition:
                self._parse_observables(observable.observable_composition.observables, to_ids=True)
            else:
                self._parse_description(indicator)

    def _parse_marking(self, handling: MarkingSpecification):
        if getattr(handling, 'marking_structures', None):
            for marking in handling.marking_structures:
                parser = self._mapping.marking_mapping(marking._XSI_TYPE)
                if parser is not None:
                    yield from getattr(self, parser)(marking)

    def _parse_observables(self, observables: Optional[Observables] = None, to_ids: bool = False):
        for observable in observables or self.stix_package.observables:
            if self._has_properties(observable):
                observable_object = observable.object_
                properties = observable_object.properties
                try:
                    attribute_type, attribute_value, compl_data = self._handle_attribute_type(properties, title=observable.title)
                except StixObjectTypeError as xsi_type:
                    self._stix_object_type_error(xsi_type, observable.id_)
                    continue
                uuid = self._sanitise_uuid(observable_object.id_)
                if isinstance(attribute_value, (str, int)):
                    if observable.object_.related_objects:
                        related_objects = observable.object_.related_objects
                        resolving = (
                            attribute_type == "url" and len(related_objects) == 1 and
                            related_objects[0].relationship.value == "Resolved_To"
                        )
                        if resolving:
                            related_ip = self._sanitise_uuid(related_objects[0].idref)
                            self.dns_objects['domain'][uuid] = {
                                "related": related_ip, "data": {
                                    "type": "text", "value": attribute_value
                                }
                            }
                            if related_ip not in self.dns_ips:
                                self.dns_ips.append(related_ip)
                            continue
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': to_ids, 'uuid': uuid}
                    if hasattr(observable, 'handling') and observable.handling:
                        attribute['Tag'] = []
                        for handling in observable.handling:
                            attribute['Tag'].extend(self._parse_marking(handling))
                    if attribute_type in ('ip-src', 'ip-dst'):
                        attribute.update(
                            {'type': attribute_type, 'value': attribute_value}
                        )
                        self.dns_objects['ip'][uuid] = attribute
                        continue
                elif attribute_value:
                    if all(isinstance(value, dict) for value in attribute_value):
                        # it is a list of attributes, so we build an object
                        self._handle_object_case(
                            attribute_type, attribute_value, compl_data,
                            to_ids=to_ids, object_uuid=uuid
                        )
                    else:
                        # it is a list of attribute values, so we add single attributes
                        for value in attribute_value:
                            self.misp_event.add_attribute(
                                **{'type': attribute_type, 'value': value, 'to_ids': to_ids}
                            )
                elif observable_object.related_objects:
                    for related_object in observable_object.related_objects:
                        relationship = related_object.relationship.value.lower().replace('_', '-')
                        self.references[uuid].append(
                            {
                                "idref": self.fetch_uuid(related_object.idref),
                                "relationship": relationship
                            }
                        )
            else:
                self._parse_description(observable)

    def _parse_threat_actor(self, threat_actor: ThreatActor):
        if getattr(threat_actor, 'title', None) is not None:
            self.galaxies.update(self._parse_galaxy(threat_actor, 'title', 'threat-actor'))
        elif getattr(threat_actor, 'identity', None) is not None:
            identity = threat_actor.identity
            if getattr(identity, 'name', None) is not None:
                self.galaxies.update(self._resolve_galaxy(identity.name, 'threat-actor'))
            elif hasattr(identity, 'specification') and getattr(identity.specification, 'party_name', None) is not None:
                party_name = identity.specification.party_name
                if getattr(party_name, 'person_names', None) is not None:
                    for person_name in party_name.person_names:
                        self.galaxies.update(
                            self._resolve_galaxy(person_name.name_elements[0].value, 'threat-actor')
                        )
                elif getattr(party_name, 'organisation_names', None) is not None:
                    for organisation_name in party_name.organisation_names:
                        self.galaxies.update(
                            self._resolve_galaxy(organisation_name.name_elements[0].value, 'threat-actor')
                        )

    def _parse_ttp(self, ttp: TTP):
        galaxies = set(self._parse_galaxies_from_ttp(ttp))
        if self._has_ttp_content(ttp):
            attributes = self._parse_attributes_from_ttp(ttp, galaxies)
            if attributes:
                for attribute in attributes:
                    misp_attribute = MISPAttribute()
                    misp_attribute.from_dict(**attribute)
                    for galaxy in galaxies:
                        misp_attribute.add_tag(galaxy)
                    self.misp_event.add_attribute(**misp_attribute)
                return
        self.galaxies.update(galaxies)

    ############################################################################
    #                   MARKING DEFINITIONS PARSING METHODS.                   #
    ############################################################################

    @staticmethod
    def _parse_AIS_marking(marking: AISMarkingStructure):
        for feature in ('is_proprietary', 'not_proprietary'):
            proprietary = getattr(marking, feature)
            if proprietary is None:
                continue
            yield f'ais-marking:AISMarking="{feature.title()}"'
            if hasattr(proprietary, 'cisa_proprietary'):
                cisa_proprietary = (
                    'true' if proprietary.cisa_proprietary.numerator == 1
                    else 'false'
                )
                yield f'ais-marking:CISA_Proprietary="{cisa_proprietary}"'
            if hasattr(proprietary, 'ais_consent'):
                consent = proprietary.ais_consent.consent
                yield f'ais-marking:AISConsent="{consent}"'
            if hasattr(proprietary, 'tlp_marking'):
                color = proprietary.tlp_marking.color
                yield f'ais-marking:TLPMarking="{color}"'

    @staticmethod
    def _parse_TLP_marking(marking: TLPMarkingStructure):
        yield f'tlp:{marking.color.lower()}'

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    def _get_event_info(self):
        if hasattr(self.stix_package, 'title'):
            return self.stix_package.title
        if hasattr(getattr(self.stix_package, 'stix_header', None), 'title'):
            return self.stix_package.stix_header.title
        return f"Imported from external STIX {self.stix_version} Package"

    @staticmethod
    def _has_properties(observable):
        if not hasattr(observable, 'object_') or not observable.object_:
            return False
        if hasattr(observable.object_, 'properties') and observable.object_.properties:
            return True
        return False

    def _has_ttp_content(self, ttp: TTP) -> bool:
        if ttp.resources is not None and ttp.resources.infrastructure is not None:
            return True
        if ttp.exploit_targets is None or ttp.exploit_targets.exploit_target is None:
            return False
        return any(
            exploit_target.item.vulnerability is not None
            for exploit_target in ttp.exploit_targets.exploit_target
        )
