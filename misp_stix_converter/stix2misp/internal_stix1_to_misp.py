#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..tools.misp_object_templates import (
    _sanitise_template_name, _UNKNOWN_TEMPLATE_NAME)
from .stix1_mapping import InternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.abstract import resources_path
from pymisp.api import describe_types
from datetime import datetime
from stix.common.related import RelatedIndicator, RelatedObservable
from stix.core import STIXPackage
from stix.exploit_target import Vulnerability, Weakness
from stix.indicator import Indicator, Observable
from stix.ttp import TTP
from stix.ttp.attack_pattern import AttackPattern
from typing import Optional

_MISP_categories = describe_types.get('categories')
_MISP_objects_path = resources_path / 'objects'
# How the export titles the TTP a `vulnerability` or `weakness` attribute is
# written as, as against the `(MISP Galaxy)` a galaxy cluster is written with
_MISP_ATTRIBUTE_TITLE_SUFFIX = ' (MISP Attribute)'


class InternalSTIX1toMISPParser(STIX1toMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = InternalSTIX1toMISPMapping

    def parse_stix_package(self, **kwargs):
        self._reset_bundle_state()
        self._set_parameters(**kwargs)
        # Every related package is merged into one MISP event - the titles,
        # dates and timestamps of all of them - so this parser has no per
        # event mode to ask for, like the External one it sits next to
        self._set_single_event(True)
        self._set_misp_event(MISPEvent())
        # The event export relates one package per event to the wrapper it
        # writes; an Attribute Collection writes its content on the package
        # itself, with no Incident to relate anything to
        if self.stix_package.related_packages:
            for item in self.stix_package.related_packages.related_package:
                self._parse_event_package(item.item)
        else:
            self._parse_attributes_collection(self.stix_package)
        self._set_distribution()
        self.misp_event.info = ' - '.join(self.titles)
        # An Incident exported without a timestamp gives the event none
        if self.dates:
            self.misp_event.date = max(self.dates)
        if self.timestamps:
            self.misp_event.timestamp = max(self.timestamps)
        self._apply_object_references()
        self._apply_event_galaxies()
        self._refuse_empty_event()

    def _parse_attributes_collection(self, package: STIXPackage):
        """Convert the package an Attribute Collection writes.

        The `to_ids` attributes are the Indicators of the package, the others
        its Observables, and there is no Incident to relate them to under
        their category: an Indicator carries it in the title the export
        writes, an Observable nowhere. The `vulnerability` and `weakness`
        attributes are TTPs, as in an event export - which has the Incident
        leverage them, where the galaxy TTPs next to them are only indicated
        by the Indicators: here the title the export gives each TTP is what
        tells the two apart.

        :param package: the package the attributes are written on
        """
        if package.timestamp:
            self._record_date_and_timestamp(package.timestamp)
        self.titles.add(self._get_package_title(package))
        if package.indicators:
            for indicator in package.indicators:
                self._parse_attribute_indicator(
                    indicator, self._category_from_title(indicator.title)
                )
        if package.observables:
            for observable in package.observables:
                self._parse_attribute_observable(observable)
        object_references = tuple(
            self._extract_uuid(ttp.id_) for ttp in (
                package.ttps.ttp if package.ttps else ()
            )
            if (ttp.title or '').endswith(_MISP_ATTRIBUTE_TITLE_SUFFIX)
        )
        self._parse_package_context(package, object_references)

    def _parse_event_package(self, package: STIXPackage):
        """Convert one related package of a MISP event export: its Incident
        and the context objects it leverages.

        :param package: the package the event was exported as
        """
        self._event = package.incidents[0]
        object_references = []
        for coa_taken in self._event.coa_taken:
            course_of_action = coa_taken.course_of_action
            # The export writes the COA taken as a reference to a Course
            # of Action of the package, which the package loop below
            # parses: a stub carrying only the reference has nothing more
            if course_of_action.id_ is None and course_of_action.idref:
                continue
            self._parse_course_of_action(course_of_action)
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
            self._record_date_and_timestamp(self._event.timestamp)
        self.titles.add(self._get_event_info(package))
        if self._event.related_indicators:
            for indicator in self._event.related_indicators.indicator:
                self._parse_indicator(indicator)
        if self._event.related_observables:
            for observable in self._event.related_observables.observable:
                self._parse_observable(observable)
        if self._event.history:
            for entry in self._event.history.history_items:
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
        self._parse_package_context(package, object_references)

    def _parse_package_context(self, package: STIXPackage,
                               object_references: tuple = ()):
        """Convert the context objects a package carries next to its content.

        Courses of action and threat actors are galaxies. So is a TTP, unless
        the Incident leverages it: the export writes the attack pattern,
        vulnerability and weakness MISP objects as the TTPs an Incident
        leverages, and those come back as the objects they were.

        :param package: the package the context objects are written on
        :param object_references: the uuids of the TTPs the Incident leverages
        """
        if package.courses_of_action:
            for course_of_action in package.courses_of_action:
                self.galaxies.update(
                    self._parse_galaxy(course_of_action, 'title', 'course_of_action')
                )
        if package.threat_actors:
            for threat_actor in package.threat_actors:
                self.galaxies.update(
                    self._parse_galaxy(threat_actor, 'title', 'threat_actor')
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

    def _reset_bundle_state(self):
        super()._reset_bundle_state()
        # Every related package of one document contributes its title, date and
        # timestamp to the single event they are merged into - which makes them
        # the state a second document must not inherit, or its event is named
        # after both and dated from whichever is the later
        self.__dates = set()
        self.__timestamps = set()
        self.__titles = set()

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
    def _parse_indicator(self, indicator: RelatedIndicator):
        # define is an indicator will be imported as attribute or object
        if indicator.relationship in _MISP_categories:
            self._parse_misp_attribute_indicator(indicator)
        else:
            self._parse_misp_object_indicator(indicator)

    def _parse_observable(self, observable: RelatedObservable):
        if observable.relationship in _MISP_categories:
            self._parse_misp_attribute_observable(observable)
        else:
            self._parse_misp_object_observable(observable)

    def _parse_ttp(self, ttp: TTP):
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    self.galaxies.update(self._parse_galaxy(attack_pattern, 'title', 'attack_pattern'))
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    if not malware_instance._XSI_TYPE or 'stix-maec' not in malware_instance._XSI_TYPE:
                        self.galaxies.update(self._parse_galaxy(malware_instance, 'title', 'malware'))
        elif ttp.exploit_targets:
            if ttp.exploit_targets.exploit_target:
                for exploit_target in ttp.exploit_targets.exploit_target:
                    if exploit_target.item.vulnerabilities:
                        for vulnerability in exploit_target.item.vulnerabilities:
                            self.galaxies.update(
                                self._parse_galaxy(vulnerability, 'title', 'vulnerability')
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
                    vulnerability_object.add_attribute(**attribute)
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
    def _parse_misp_attribute_indicator(self, indicator: RelatedIndicator):
        self._parse_attribute_indicator(
            indicator.item, str(indicator.relationship)
        )

    def _parse_misp_attribute_observable(self, observable: RelatedObservable):
        if observable.item:
            self._parse_attribute_observable(
                observable.item, str(observable.relationship)
            )

    def _parse_attribute_indicator(
            self, indicator: Indicator, category: Optional[str] = None):
        """Convert the Indicator a `to_ids` attribute was exported as.

        :param indicator: the Indicator itself - the item of the Related
            Indicator an event export relates to its Incident, the Indicator
            an Attribute Collection writes on the package
        :param category: the MISP category, from the relationship of the
            former or the title of the latter - None when neither names one,
            and pymisp's default for the type stands in
        """
        # An Indicator carrying rules and no observable converts to nothing
        if not indicator.observable:
            return
        misp_attribute = {'to_ids': True}
        if category is not None:
            misp_attribute['category'] = category
        if indicator.timestamp:
            misp_attribute['timestamp'] = self._timestamp_from_date(
                indicator.timestamp
            )
        misp_attribute.update(self._sanitise_attribute_uuid(indicator.id_))
        self._parse_misp_attribute(
            indicator.observable, misp_attribute, indicator.id_, to_ids=True
        )

    def _parse_attribute_observable(
            self, observable: Observable, category: Optional[str] = None):
        """Convert the Observable an attribute with `to_ids` unset was
        exported as.

        :param observable: the Observable itself - the item of the Related
            Observable an event export relates to its Incident, the Observable
            an Attribute Collection writes on the package
        :param category: the MISP category the relationship of the former
            carries - the latter carries none, and pymisp's default for the
            type stands in
        """
        misp_attribute = {'to_ids': False}
        if category is not None:
            misp_attribute['category'] = category
        misp_attribute.update(self._sanitise_attribute_uuid(observable.id_))
        self._parse_misp_attribute(observable, misp_attribute, observable.id_)

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
                        properties
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
                'Unable to parse the Indicator object '
                f'with id {indicator.item.id_}'
            )
        else:
            self._fill_misp_object(indicator.item, name, to_ids=True)

    def _parse_misp_object_observable(self, observable: Observable):
        name = self._define_name(observable.item, observable.relationship)
        try:
            self._fill_misp_object(observable.item, name)
        except Exception:
            self._add_error(
                'Unable to parse the Observable '
                f'object with id {observable.item.id_}'
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
            if name is None:
                # A composition the export named in no way this parser reads:
                # the attributes are kept, under a name that resolves nothing
                self._unnamed_composition_warning(item.id_)
                name = _UNKNOWN_TEMPLATE_NAME
            # The name is read from the Observable id the export wrote it in,
            # and pymisp joins it into a filesystem path to find the template:
            # a name that is not a plain template name is kept out of that join
            name, rejected_name = _sanitise_template_name(name)
            misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
            self._sanitise_object_uuid(misp_object, item.id_)
            if rejected_name is not None:
                self._invalid_template_name_warning(rejected_name, item.id_)
                self._record_rejected_template_name(misp_object, rejected_name)
            if to_ids:
                observables = item.observable.observable_composition.observables
                misp_object.timestamp = self._timestamp_from_date(item.timestamp)
            else:
                observables = item.observable_composition.observables
            args = (misp_object, observables, to_ids)
            self._handle_file_composition(*args) if name == 'file' else self._handle_composition(*args)
            self.misp_event.add_object(misp_object)
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

    @staticmethod
    def _category_from_title(title: Optional[str]) -> Optional[str]:
        """Read the MISP category off the title of an Attribute Collection
        Indicator.

        The export writes `{category}: {value} (MISP Attribute)`: the one place
        the category travels when there is no Incident to relate the Indicator
        to under it. A title of another shape names no category.

        :param title: the Indicator title
        :return: the category, None when the title names none
        """
        if not title:
            return None
        category = title.split(': ', 1)[0]
        return category if category in _MISP_categories else None

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

    def _define_name(self, observable: Observable, relationship) -> Optional[str]:
        """Name the MISP object an Observable came from.

        Only an observable composition needs one: the export writes the object
        name into the Observable id it gives the composition, and a simple
        Observable takes its name from the CybOX properties themselves, in
        `_handle_attribute_type`.

        :param observable: the Observable the MISP object was exported as
        :param relationship: the MISP meta-category the export wrote
        :return: the object template name, None when the Observable names none
        """
        observable_id = observable.id_
        if relationship == "file":
            return "registry-key" if "WinRegistryKey" in observable_id else "file"
        if "Custom" in observable_id:
            return observable_id.split("Custom")[0].split(":")[1]
        # Whatever the meta-category: the export names every composition the
        # same way, and only the composition branch below uses the name
        if "ObservableComposition" in observable_id:
            return observable_id.split("_")[0].split(":")[1]

    def _unnamed_composition_warning(self, object_id: str):
        self._add_warning(
            f'Unable to define the MISP object name of the Observable '
            f'composition with id {object_id}: converted as a '
            f'{_UNKNOWN_TEMPLATE_NAME} object.'
        )

    def _get_event_info(self, package: Optional[STIXPackage] = None):
        # `hasattr` is useless here: the Incident always carries a `title`
        # field, set to None when absent, so only testing the value makes the
        # fallbacks reachable.
        if getattr(self._event, 'title', None):
            return self._event.title
        return self._get_package_title(package)

    def _get_package_title(self, package: Optional[STIXPackage]):
        # The STIX header lives on the package, not on the Incident: the
        # per-event related package carries this event's own title, and the
        # wrapper package only the collection-level one - which is the one
        # title an Attribute Collection writes.
        for candidate in (package, self.stix_package):
            title = getattr(
                getattr(candidate, 'stix_header', None), 'title', None
            )
            if title:
                return title
        return f"Imported from STIX {self.stix_version} Package generated with MISP"

    def _record_date_and_timestamp(self, stix_date: datetime):
        # The date and timestamp the event takes are the latest of the
        # Incidents merged into it - or of the one package an Attribute
        # Collection writes them on
        try:
            self.dates.add(stix_date.date())
        except AttributeError:
            self.dates.add(stix_date)
        self.timestamps.add(self._timestamp_from_date(stix_date))
