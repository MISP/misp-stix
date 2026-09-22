#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..tools.misp_object_templates import (
    _sanitise_template_name, _template_attribute_types,
    _UNKNOWN_TEMPLATE_NAME)
from .stix1_mapping import InternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.abstract import resources_path
from pymisp.api import describe_types
from pymisp.exceptions import PyMISPError
from datetime import datetime
from stix.campaign import Campaign
from stix.coa import CourseOfAction
from stix.common.identity import Identity
from stix.common.related import RelatedIndicator, RelatedObservable
from stix.core import STIXPackage
from stix.exploit_target import Vulnerability, Weakness
from stix.incident.affected_asset import AffectedAsset
from stix.indicator import Indicator, Observable
from stix.ttp import TTP
from stix.ttp.attack_pattern import AttackPattern
from typing import Iterator, Optional

_MISP_categories = describe_types.get('categories')
_MISP_objects_path = resources_path / 'objects'
# How the export titles the TTP it writes a galaxy cluster as, against the
# `(MISP Attribute)` and `(MISP Object)` it titles the TTP of an attribute or
# an object with: what tells a cluster from the content written next to it
_MISP_GALAXY_TITLE_SUFFIX = ' (MISP Galaxy)'
# What the export puts before the value of a `target-external` attribute in
# the name line of the CIQ identity it writes the attribute as
_MISP_EXTERNAL_TARGET_PREFIX = 'External target: '


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
        attributes are TTPs, next to the galaxy TTPs the Indicators indicate,
        and the package context reads the title the export gives each.

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
        self._parse_package_context(package)

    def _parse_event_package(self, package: STIXPackage):
        """Convert one related package of a MISP event export: its Incident
        and the context objects it leverages.

        :param package: the package the event was exported as
        """
        self._event = package.incidents[0]
        # The export writes the Course of Action of a `course-of-action`
        # object and the one of an event galaxy alike: on the package, taken
        # by the Incident through a stub carrying the reference - and the
        # timestamp of the object, which a galaxy cluster has none of. The
        # package loop below parses the referenced ones; a Course of Action
        # written in full where the stub goes is parsed for what it carries
        object_courses_of_action = set()
        for coa_taken in self._event.coa_taken:
            course_of_action = coa_taken.course_of_action
            if course_of_action.id_ is None and course_of_action.idref:
                if course_of_action.timestamp is not None:
                    object_courses_of_action.add(
                        self._extract_uuid(course_of_action.idref)
                    )
                continue
            self._parse_course_of_action(course_of_action)
        if self._event.timestamp:
            self._record_date_and_timestamp(self._event.timestamp)
        self.titles.add(self._get_event_info(package))
        if self._event.related_indicators:
            for indicator in self._event.related_indicators.indicator:
                self._parse_indicator(indicator)
        if self._event.related_observables:
            for observable in self._event.related_observables.observable:
                self._parse_observable(observable)
        # The `target-*` attributes: five kinds as the Victims of the
        # Incident, the `target-machine` as its Affected Assets
        if self._event.victims:
            for victim in self._event.victims:
                self._parse_victim_identity(victim)
        if self._event.affected_assets:
            for affected_asset in self._event.affected_assets:
                self._parse_affected_asset(affected_asset)
        # The event tags: the handling the export writes them on, plus the
        # `misp:tool` journal entry below. Nothing dedupes them here - pymisp
        # adds a tag name it already has once
        for tag in self._read_markings(self._event.handling):
            self.misp_event.add_tag(tag)
        if self._event.history:
            for entry in self._event.history.history_items:
                journal_entry = entry.journal_entry.value
                try:
                    entry_type, entry_value = journal_entry.split(': ')
                    if entry_type == "MISP Tag":
                        self.misp_event.add_tag(entry_value)
                    elif entry_type.startswith('attribute['):
                        _, category, attribute_type = entry_type.split('[')
                        # The type is read off the journal entry text: what
                        # MISP has no such type for is the one attribute lost
                        self._add_attribute(
                            {
                                'type': attribute_type[:-1],
                                'category': category[:-1],
                                'value': entry_value
                            },
                            self._event.id_
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
                self._add_attribute(
                    {'type': 'link', 'value': reference}, self._event.id_
                )
        self._parse_package_context(
            package, frozenset(object_courses_of_action)
        )

    def _parse_package_context(self, package: STIXPackage,
                               object_courses_of_action: frozenset = frozenset()):
        """Convert the context objects a package carries next to its content.

        Campaigns are `campaign-name` attributes. Threat actors are galaxies.
        Courses of action and TTPs are galaxies or MISP objects, and the
        export writes both kinds alike, referenced from the Incident the same
        way: a TTP is told by the title the export gives it, a Course of
        Action by what it carries - the fields a cluster has none of, or the
        timestamp of the object the Incident took it with.

        :param package: the package the context objects are written on
        :param object_courses_of_action: the uuids of the Courses of Action
            the Incident took stamped with the timestamp of a MISP object
        """
        if package.campaigns:
            for campaign in package.campaigns:
                self._parse_campaign(campaign)
        if package.courses_of_action:
            for course_of_action in package.courses_of_action:
                if self._is_course_of_action_object(
                        course_of_action, object_courses_of_action):
                    self._parse_course_of_action(course_of_action)
                    continue
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
                if (ttp.title or '').endswith(_MISP_GALAXY_TITLE_SUFFIX):
                    self._parse_ttp(ttp)
                else:
                    self._parse_ttp_object(ttp)
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

    def _parse_affected_asset(self, affected_asset: AffectedAsset):
        """Convert the Affected Asset a `target-machine` attribute was
        exported as: a description alone - `{value} ({comment})` when the
        attribute carried a comment - with no id and no Record Title.

        The last ` (` is the export's own, so a value holding parentheses
        and the comment behind it come back apart - and a value ending in
        `)` with no comment loses its tail to the comment. Nothing derives
        the uuid: two identical machines would share it, so pymisp's random
        one stands in. An Affected Asset with no description is no export of
        ours, and the error records it.

        :param affected_asset: the Affected Asset of the Incident
        """
        description = affected_asset.description
        if description is None or not description.value:
            self._add_error(
                'Unable to convert an Affected Asset of the Incident with id '
                f'{self._event.id_}: no description to read a target-machine '
                'attribute from'
            )
            return
        value, comment = self._split_affected_asset_description(
            description.value
        )
        misp_attribute = {'type': 'target-machine', 'value': value}
        if comment is not None:
            misp_attribute['comment'] = comment
        self._add_attribute(misp_attribute, self._event.id_)

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

    def _parse_campaign(self, campaign: Campaign):
        """Convert the Campaign a `campaign-name` attribute was exported as:
        the value as its name, the category off the Record Title, the uuid,
        the timestamp, the comment it writes as the description and the tags
        as the handling. The description needs no guard as an Indicator's
        does: the export writes it only when the attribute has a comment of
        its own. A Campaign with no name is no export of ours, and the error
        records it.

        :param campaign: the Campaign the package carries
        """
        if not campaign.names:
            self._add_error(
                f'Unable to convert the Campaign with id {campaign.id_}: '
                'no name to read a campaign-name attribute from'
            )
            return
        misp_attribute = {
            'type': 'campaign-name', 'value': campaign.names[0].value
        }
        category = self._category_from_title(campaign.title)
        if category is not None:
            misp_attribute['category'] = category
        if campaign.timestamp:
            misp_attribute['timestamp'] = self._timestamp_from_date(
                campaign.timestamp
            )
        comment = self._read_comment(campaign.description)
        if comment is not None:
            misp_attribute['comment'] = comment
        tags = tuple(self._read_markings(campaign.handling))
        if tags:
            misp_attribute['Tag'] = list(tags)
        misp_attribute.update(self._sanitise_attribute_uuid(campaign.id_))
        self._add_attribute(misp_attribute, campaign.id_)

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
        """Convert the TTP a galaxy cluster was exported as: the galaxy tag
        its attack pattern, malware, vulnerability or tool names.

        :param ttp: the TTP, titled `(MISP Galaxy)`
        """
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

    def _parse_ttp_object(self, ttp: TTP):
        """Convert the TTP a MISP attribute or object was exported as: the
        attack pattern, vulnerability or weakness it carries, or the identity
        it targets - how an Attribute Collection, with no Incident to make a
        Victim of, writes a `target-*` attribute. One carrying none of the
        four has nothing the parser reads an attribute or an object from, and
        the error records it.

        The context the TTP carries is read once here and handed to whichever
        of the four builds the record: the tags off the TTP's handling, the
        comment off the description of the Exploit Target the attribute was
        written into. The tags reach a record that takes them - a `target-*`
        attribute, a `vulnerability` attribute carrying its id alone - and
        the warning records the ones that land on a MISP object instead.

        :param ttp: the TTP, titled `(MISP Attribute)` or `(MISP Object)`
        """
        ttp_id = self._extract_uuid(ttp.id_)
        tags = tuple(self._read_markings(ttp.handling))
        converted = False
        if ttp.behavior and ttp.behavior.attack_patterns:
            for attack_pattern in ttp.behavior.attack_patterns:
                self._parse_attack_pattern_object(attack_pattern, ttp_id)
                if tags:
                    self._object_markings_warning()
            converted = True
        if ttp.victim_targeting and ttp.victim_targeting.identity:
            self._parse_victim_identity(
                ttp.victim_targeting.identity, ttp.timestamp, tags
            )
            converted = True
        if ttp.exploit_targets and ttp.exploit_targets.exploit_target:
            for exploit_target in ttp.exploit_targets.exploit_target:
                comment = self._read_comment(exploit_target.item.description)
                if exploit_target.item.vulnerabilities:
                    for vulnerability in exploit_target.item.vulnerabilities:
                        self._parse_vulnerability_object(
                            vulnerability, ttp_id, comment, tags
                        )
                    converted = True
                if exploit_target.item.weaknesses:
                    for weakness in exploit_target.item.weaknesses:
                        self._parse_weakness_object(
                            weakness, ttp_id, comment, tags
                        )
                    converted = True
        if not converted:
            self._unconverted_ttp_error(ttp.id_)

    def _parse_victim_identity(
            self, identity: Identity, timestamp: Optional[datetime] = None,
            tags: tuple = ()):
        """Convert the CIQ identity a `target-*` attribute was exported as:
        the Victim of the Incident an Event Collection writes, the identity a
        TTP targets in an Attribute Collection.

        The type is told by the one CIQ identity field the export fills, and
        the five are disjoint: an electronic address identifier is a
        `target-email`, a name line a `target-external`, an address a
        `target-location`, an organisation name a `target-org`, a person name
        a `target-user`. The category is read off the Record Title the
        identity is named with. An identity filling no field or several, or
        named with no Record Title, is no export of ours - a hand-edited or
        misclassified document - and the error records it.

        :param identity: the CIQ identity
        :param timestamp: the timestamp of the TTP targeting the identity - a
            Victim travels with none
        :param tags: the tags the TTP targeting the identity carries on its
            handling - a Victim carries none, the Incident holding it does
        """
        targets = list(self._read_target_identity_fields(identity))
        if len(targets) != 1:
            self._unconverted_identity_error(
                identity.id_,
                'no single CIQ identity field to read a target attribute from'
            )
            return
        category = self._category_from_title(identity.name)
        if category is None:
            self._unconverted_identity_error(
                identity.id_, 'no MISP category to read off its name'
            )
            return
        attribute_type, value = targets[0]
        misp_attribute = {
            'type': attribute_type, 'value': value, 'category': category
        }
        if timestamp:
            misp_attribute['timestamp'] = self._timestamp_from_date(timestamp)
        if tags:
            misp_attribute['Tag'] = list(tags)
        misp_attribute.update(self._sanitise_attribute_uuid(identity.id_))
        self._add_attribute(misp_attribute, identity.id_)

    def _parse_vulnerability_object(
            self, vulnerability: Vulnerability, ttp_id: str,
            comment: Optional[str] = None, tags: tuple = ()):
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
                if comment is not None:
                    attributes['comment'] = comment
                if tags:
                    attributes['Tag'] = list(tags)
                self._add_attribute(attributes, ttp_id)
            else:
                vulnerability_object = MISPObject('vulnerability')
                vulnerability_object.uuid = ttp_id
                if comment is not None:
                    vulnerability_object.comment = comment
                if tags:
                    self._object_markings_warning()
                for attribute in attributes:
                    vulnerability_object.add_attribute(**attribute)
                self.misp_event.add_object(vulnerability_object)

    def _parse_weakness_object(
            self, weakness: Weakness, ttp_id: str,
            comment: Optional[str] = None, tags: tuple = ()):
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
            if comment is not None:
                weakness_object.comment = comment
            if tags:
                self._object_markings_warning()
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

        Most attributes are the observable the Indicator carries. A `snort`
        or `yara` attribute is the rule it carries as a test mechanism instead,
        with no observable - the one shape the export writes an Indicator with
        no observable in - and reads back one attribute per rule: a Snort
        mechanism may carry several, never written by us, and the Indicator's
        uuid goes to the first. An Indicator carrying no observable and no
        rule is no export of ours, and the error records it.

        The comment and the tags come back with it: the export writes the
        comment as the description, falling back to the Record Title when
        there is none, and the tags as the handling. An Indicator yielding
        several attributes gives each of them both - a uuid is an identity
        and goes to the first alone, a comment and a tag are context the
        Indicator carried for every rule it held.

        :param indicator: the Indicator itself - the item of the Related
            Indicator an event export relates to its Incident, the Indicator
            an Attribute Collection writes on the package
        :param category: the MISP category, from the relationship of the
            former or the title of the latter - None when neither names one,
            and pymisp's default for the type stands in
        """
        misp_attribute = {'to_ids': True}
        if category is not None:
            misp_attribute['category'] = category
        if indicator.timestamp:
            misp_attribute['timestamp'] = self._timestamp_from_date(
                indicator.timestamp
            )
        comment = self._read_comment(indicator.description, indicator.title)
        if comment is not None:
            misp_attribute['comment'] = comment
        tags = tuple(self._read_markings(indicator.handling))
        if tags:
            misp_attribute['Tag'] = list(tags)
        if indicator.observable:
            misp_attribute.update(self._sanitise_attribute_uuid(indicator.id_))
            self._parse_misp_attribute(
                indicator.observable, misp_attribute, indicator.id_, to_ids=True
            )
            return
        rules = list(self._read_test_mechanisms(indicator))
        if not rules:
            self._unconverted_indicator_error(indicator.id_)
            return
        for index, (attribute_type, rule) in enumerate(rules):
            attribute = {'type': attribute_type, 'value': rule, **misp_attribute}
            if index == 0:
                attribute.update(self._sanitise_attribute_uuid(indicator.id_))
            self._add_attribute(attribute, indicator.id_)

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
                    self._handle_attribute_case(
                        attribute_type, attribute_value, compl_data,
                        misp_attribute, stix_object_id
                    )
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
                composite = self._composite_type(attribute_dict)
                if composite is None:
                    # The values a composition holds pair into no MISP
                    # composite type: there is no attribute to build, and
                    # unpacking the nothing that was returned used to cost the
                    # whole package
                    self._unconvertible_composition_error(
                        sorted(attribute_dict), stix_object_id
                    )
                    return
                attribute_type, attribute_value = composite
                self._add_attribute(
                    {
                        'type': attribute_type, 'value': attribute_value,
                        **misp_attribute
                    },
                    stix_object_id
                )

    # Parse STIX object that we know will give MISP objects
    def _parse_misp_object_indicator(self, indicator: Indicator):
        """Convert the Indicator a `to_ids` MISP object was exported as.

        The comment comes back through the object template: the export writes
        it as the description and falls back to the template's own
        description, which every MISP object carries, when the object has no
        comment of its own. The description travels raw, and the template it
        is told from is the one of the object the content builds - the name
        here only names the compositions. The handling does not come back - it
        holds the tags of every attribute the object held merged into one set,
        and a MISP object takes no tag - so the warning records what is
        dropped.

        :param indicator: the Related Indicator the Incident carries
        """
        name = self._define_name(indicator.item.observable, indicator.relationship)
        if name == 'passive-dns' and str(indicator.relationship) != "misc":
            self._add_error(
                'Unable to parse the Indicator object '
                f'with id {indicator.item.id_}'
            )
        else:
            if any(self._read_markings(indicator.item.handling)):
                self._object_markings_warning()
            self._fill_misp_object(
                indicator.item, name, to_ids=True,
                description=indicator.item.description,
                title=indicator.item.title
            )

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
    def _fill_misp_object(self, item, name, to_ids=False, description=None,
                          title=None):
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
            # Guarded as one record, like every other object: what pymisp
            # refuses inside a composition costs that object and no more
            try:
                self._build_composition_object(
                    item, name, rejected_name, to_ids, description, title
                )
            except PyMISPError as exception:
                self._refused_object_error(
                    name, exception, self._sanitise_uuid(item.id_)
                )
        else:
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            self._parse_observable_object(
                properties, to_ids, self._sanitise_uuid(item.id_), item.id_,
                name=name, description=description, title=title
            )

    def _build_composition_object(self, item, name: str,
                                  rejected_name: Optional[str], to_ids: bool,
                                  description, title):
        """Build the MISP object an Observable composition was exported as,
        and add it to the event.

        Called through the guard in `_fill_misp_object`, which is where the
        refusal of any record built here is recorded.

        :param item: the Indicator or Observable carrying the composition
        :param name: the object template name, sanitised
        :param rejected_name: the name `_sanitise_template_name` refused, None
            where it kept the one the document carried
        :param to_ids: the `to_ids` flag the whole composition was written with
        :param description: the STIX description field, or None
        :param title: the Record Title, where the shape carries one
        """
        misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
        self._sanitise_object_uuid(misp_object, item.id_)
        comment = self._read_object_comment(name, description, title)
        if comment is not None:
            misp_object.comment = comment
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

    def _handle_composition(self, misp_object, observables, to_ids):
        for observable in observables:
            properties = observable.object_.properties
            try:
                attribute = self._handle_attribute_type(properties)
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                continue
            attribute_type, attribute_value, relation = attribute
            filename = self._filename_residue(relation)
            if filename is not None:
                # In an object the two halves are two relations, the hash
                # naming its own the way every hash read from a composition
                # does
                self._add_filename_relation(misp_object, filename, to_ids)
                relation = attribute_type
            misp_attribute = MISPAttribute()
            misp_attribute.type = attribute_type
            misp_attribute.value = attribute_value
            misp_attribute.object_relation = relation
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
        template_types = _template_attribute_types('file')
        for observable in observables:
            try:
                attribute_type, attribute_value, compl_data = self._handle_attribute_type(
                    observable.object_.properties, title=observable.title
                )
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                continue
            if isinstance(attribute_value, str):
                filename = self._filename_residue(compl_data)
                if filename is not None:
                    # Both halves are relations the `file` template defines,
                    # so the pairing is all that is lost
                    self._add_filename_relation(misp_object, filename, to_ids)
                    compl_data = None
                # The MISP type the content named is the object relation too:
                # a type the `file` template does not define is checked
                # against MISP's own, rather than handed to pymisp, which
                # refuses it and costs the whole object
                attribute = self._read_derived_attribute(
                    attribute_type, attribute_value, template_types,
                    observable.id_
                )
                if attribute is None:
                    continue
                attribute_type, attribute_value, relation = attribute
                misp_object.add_attribute(
                    **{
                        'type': attribute_type, 'value': attribute_value,
                        'object_relation': relation, 'to_ids': to_ids,
                        'data': compl_data
                    }
                )
            else:
                for attribute in attribute_value:
                    attribute['to_ids'] = to_ids
                    misp_object.add_attribute(**attribute)
        return misp_object

    # Create a MISP attribute and add it in its MISP object
    def _parse_observable_object(self, properties, to_ids, uuid, object_id,
                                 name=None, description=None, title=None):
        attribute_type, attribute_value, compl_data = self._handle_attribute_type(properties)
        if isinstance(attribute_value, (str, int)):
            attribute = {'to_ids': to_ids, 'uuid': uuid}
            # An object whose content folds into a single attribute has no
            # template of its own to tell the description from a comment: the
            # name the Observable carries is the only one there is
            comment = self._read_object_comment(name, description, title)
            if comment is not None:
                attribute['comment'] = comment
            self._handle_attribute_case(
                attribute_type, attribute_value, compl_data, attribute,
                object_id
            )
        else:
            self._handle_object_case(
                attribute_type, attribute_value, compl_data, to_ids=to_ids,
                object_uuid=uuid, description=description, title=title
            )

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

    # Return type & value of a composite attribute in MISP - None where the
    # values the composition holds pair into no MISP composite type, which the
    # caller records rather than unpacking
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
            for feature in ('ip-src', 'ip-dst'):
                if feature in attributes:
                    return (
                        "domain|ip",
                        f"{attributes['domain']}|{attributes[feature]}"
                    )

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

    def _is_course_of_action_object(
            self, course_of_action: CourseOfAction,
            object_courses_of_action: frozenset) -> bool:
        """Tell the Course of Action a `course-of-action` object was exported
        as from the one a galaxy cluster was.

        A cluster is written as a title and a description, and taken by the
        Incident through a bare reference: a field beyond those two, or a
        reference stamped with the object's timestamp, is the object's.

        :param course_of_action: the Course of Action the package carries
        :param object_courses_of_action: the uuids of the Courses of Action
            the Incident took stamped with the timestamp of a MISP object
        :return: whether the Course of Action is a MISP object
        """
        if self._extract_uuid(course_of_action.id_) in object_courses_of_action:
            return True
        return any(
            getattr(course_of_action, field) is not None
            for field in self._mapping.course_of_action_mapping()
            if field != 'description'
        )

    @staticmethod
    def _read_target_identity_fields(
            identity: Identity) -> Iterator[tuple[str, str]]:
        """Read the `target-*` type and the value off each CIQ identity field
        the identity fills - the export fills one, with one value.

        :param identity: the CIQ identity, or a plain Identity carrying no
            specification and filling no field
        :return: the type and the value of each filled field
        """
        specification = getattr(identity, 'specification', None)
        if specification is None:
            return
        for identifier in specification.electronic_address_identifiers or ():
            if identifier.value:
                yield 'target-email', identifier.value
        party_name = specification.party_name
        if party_name is not None:
            for name_line in party_name.name_lines or ():
                if name_line.value:
                    yield 'target-external', name_line.value.removeprefix(
                        _MISP_EXTERNAL_TARGET_PREFIX
                    )
            for organisation_name in party_name.organisation_names or ():
                for element in organisation_name.name_elements or ():
                    if element.value:
                        yield 'target-org', element.value
            for person_name in party_name.person_names or ():
                for element in person_name.name_elements or ():
                    if element.value:
                        yield 'target-user', element.value
        for address in specification.addresses or ():
            free_text_address = address.free_text_address
            if free_text_address is not None:
                for address_line in free_text_address.address_lines or ():
                    if address_line:
                        yield 'target-location', address_line

    @staticmethod
    def _split_affected_asset_description(
            description: str) -> tuple[str, Optional[str]]:
        """Split the description of an Affected Asset into the value and the
        comment the export folded behind it as `{value} ({comment})`.

        :param description: the description
        :return: the value and the comment - the whole description and None
            when it folds no comment, or nothing before the fold
        """
        if description.endswith(')') and ' (' in description:
            value, comment = description[:-1].rsplit(' (', 1)
            if value:
                return value, comment
        return description, None

    def _unconverted_identity_error(self, identity_id: str, reason: str):
        self._add_error(
            f'Unable to convert the Victim identity with id {identity_id}: '
            f'{reason}'
        )

    def _unconverted_indicator_error(self, indicator_id: str):
        self._add_error(
            f'Unable to convert the Indicator with id {indicator_id}: no '
            'observable or test mechanism rule to read a MISP attribute from'
        )

    def _unconverted_ttp_error(self, ttp_id: str):
        self._add_error(
            f'Unable to convert the TTP with id {ttp_id}: no attack pattern, '
            'vulnerability, weakness or victim targeting to read a MISP '
            'attribute or object from'
        )

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
