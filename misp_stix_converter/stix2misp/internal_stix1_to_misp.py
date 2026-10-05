#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..tools.misp_object_templates import (
    _sanitise_template_name, _template_attribute_types,
    _UNKNOWN_TEMPLATE_NAME)
from .stix1_mapping import InternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from pymisp import MISPEvent, MISPObject
from pymisp.abstract import resources_path
from pymisp.api import describe_types
from pymisp.exceptions import PyMISPError
import re
from cybox.common.vocabs import ObjectRelationship
from cybox.core import RelatedObject
from cybox.objects.win_registry_key_object import WinRegistryKey
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
# A `link`, a `url` and a `uri` travel as the same URI object, the category on
# the relationship: under a category a `url` may not take, the URI can only
# have been a `link`
_LINK_ONLY_CATEGORIES = frozenset(
    category for category, types
    in describe_types['category_type_mappings'].items()
    if 'link' in types and 'url' not in types
)
_MISP_objects_path = resources_path / 'objects'
# How the export titles the TTP it writes a galaxy cluster as, against the
# `(MISP Attribute)` and `(MISP Object)` it titles the TTP of an attribute or
# an object with: what tells a cluster from the content written next to it
_MISP_GALAXY_TITLE_SUFFIX = ' (MISP Galaxy)'
# The tail of the `{meta-category}: {name} (MISP Object)` Record Title
_MISP_OBJECT_TITLE_SUFFIX = ' (MISP Object)'
# What the export puts before the value of a `target-external` attribute in
# the name line of the CIQ identity it writes the attribute as
_MISP_EXTERNAL_TARGET_PREFIX = 'External target: '
# The comment of the one attribute the export writes as the package header
# description rather than as a journal entry
_MISP_HEADER_DESCRIPTION_COMMENT = 'Imported from STIX header description'
# `attribute[Category][type]`, the journal entry grammar MISP core's own STIX
# 1 export wrote, next to the `Attribute (Category - type)` this one writes
_LEGACY_JOURNAL_ATTRIBUTE = re.compile(r'^attribute\[([^\]]+)\]\[([^\]]+)\]$')
_JOURNAL_ATTRIBUTE_PREFIX = 'Attribute ('
# The value slot of a galaxy tag, `misp-galaxy:{galaxy type}="{value}"`
_GALAXY_TAG = re.compile(r'^misp-galaxy:[^=]+="(.*)"$')


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
        if self.__unread_journal_entries:
            self._unread_journal_entries_warning(self.__unread_journal_entries)
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
        # package loop below parses the referenced ones, stamped with the
        # timestamp of the stub - the full one may carry the export time; a
        # Course of Action written in full where the stub goes is parsed for
        # what it carries
        object_courses_of_action = {}
        for coa_taken in self._event.coa_taken:
            course_of_action = coa_taken.course_of_action
            if course_of_action.id_ is None and course_of_action.idref:
                if course_of_action.timestamp is not None:
                    object_courses_of_action[
                        self._extract_uuid(course_of_action.idref)
                    ] = self._timestamp_from_date(course_of_action.timestamp)
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
        # adds a tag name it already has once. The handling ones are what the
        # event carried: an Incident holding one is not an empty event, the
        # tag of a galaxy no STIX 1 construct holds being all it may carry
        for tag in self._read_markings(self._event.handling):
            self.misp_event.add_tag(tag)
            self.event_tags.add(tag)
        if self._event.history:
            for entry in self._event.history.history_items:
                self._parse_journal_entry(entry.journal_entry.value)
        self._parse_header_description(package)
        if self._event.information_source and self._event.information_source.references:
            for reference in self._event.information_source.references:
                self._add_attribute(
                    {'type': 'link', 'value': reference}, self._event.id_
                )
        self._parse_package_context(package, object_courses_of_action)

    def _apply_event_galaxies(self):
        """Add the galaxy tags the STIX constructs name to the event, but the
        ones an event tag already names the cluster of.

        A construct names a cluster by its value alone, and the tag read off
        it is typed after the construct: a `ransomware` cluster exported as a
        malware TTP reads as a `mitre-malware` tag. The export keeps the tag
        of a cluster, galaxy type included, on the handling of the record
        carrying it - the Incident, an attribute, the one a MISP object
        merges the ones of its attributes into, read onto the event - so a
        tag of the same value read anywhere in the event is the cluster the
        construct names. Matched on value, two clusters of one value in two
        galaxies on two records collide, and the construct one is not added.
        """
        attributes = (
            *self.misp_event.attributes,
            *(attribute for misp_object in self.misp_event.objects
              for attribute in misp_object.attributes)
        )
        carried = {
            value for value in (
                self._galaxy_tag_value(tag.name) for tag in (
                    *self.misp_event.tags,
                    *(tag for attribute in attributes for tag in attribute.tags)
                )
            )
            if value is not None
        }
        for tag_name in sorted(self.galaxies):
            if self._galaxy_tag_value(tag_name) not in carried:
                self.misp_event.add_tag(tag_name)

    @staticmethod
    def _galaxy_tag_value(tag_name: str) -> Optional[str]:
        match = _GALAXY_TAG.match(tag_name)
        return match.group(1) if match is not None else None

    def _parse_journal_entry(self, journal_entry: str):
        """Convert one journal entry of the Incident History.

        The export writes the event tags, the threat level, and the
        attributes with no CybOX shape - `comment`, `text` and `other` - as
        `Attribute (Category - type): value`. Documents MISP core exported
        write those as `attribute[Category][type]: value`, and both grammars
        are read. An entry is split once, on the first `': '`: what follows
        is the value, whatever it holds. An entry matching none of them is
        counted, the document warned about once.

        :param journal_entry: the text of the journal entry
        """
        entry_type, separator, entry_value = journal_entry.partition(': ')
        if not separator:
            self.__unread_journal_entries += 1
            return
        if entry_type == 'MISP Tag':
            self.misp_event.add_tag(entry_value)
            return
        if entry_type == 'Event Threat Level':
            threat_level = self._mapping.threat_level_mapping(entry_value)
            if threat_level is not None:
                self.misp_event.threat_level_id = threat_level
            return
        if entry_type.startswith(_JOURNAL_ATTRIBUTE_PREFIX) and entry_type.endswith(')'):
            # No MISP type holds ` - `, so the type splits off the right
            category, separator, attribute_type = entry_type[
                len(_JOURNAL_ATTRIBUTE_PREFIX):-1
            ].rpartition(' - ')
            if separator:
                self._add_journal_attribute(
                    category, attribute_type, entry_value
                )
                return
        legacy = _LEGACY_JOURNAL_ATTRIBUTE.match(entry_type)
        if legacy is not None:
            self._add_journal_attribute(*legacy.groups(), entry_value)
            return
        self.__unread_journal_entries += 1

    def _add_journal_attribute(self, category: str, attribute_type: str,
                               value: str):
        """Add the attribute a journal entry carries.

        The entry holds the category, the type and the value, nothing else:
        the uuid is derived from the Incident id, stable across two reads of
        one document and not the original. The type is read off the entry
        text, and what MISP has no such type for is the one attribute lost.

        :param category: the category the entry names
        :param attribute_type: the type the entry names
        :param value: the value
        """
        attribute = {'type': attribute_type, 'value': value}
        # pymisp raises a bare `KeyError` for a category it does not know,
        # where it gives the type its default one
        if category in _MISP_categories:
            attribute['category'] = category
        if self._event.id_:
            attribute['uuid'] = str(
                self._create_v5_uuid(
                    f'{self._event.id_} - {attribute_type} - {value}'
                )
            )
        self._add_attribute(attribute, self._event.id_)

    def _parse_header_description(self, package: STIXPackage):
        """Convert the header description of an event package.

        The export writes the attribute commented as imported from a header
        description back to the header it came from, and reads here as a
        `comment` attribute carrying that comment, so a new export puts it
        back in the header. The original type is not on the wire, nor the
        uuid, derived from the package id.

        :param package: the package the Incident is written on
        """
        description = getattr(package.stix_header, 'description', None)
        if description is None or not description.value:
            return
        attribute = {
            'type': 'comment', 'category': 'Other',
            'value': description.value,
            'comment': _MISP_HEADER_DESCRIPTION_COMMENT
        }
        if package.id_:
            attribute['uuid'] = str(
                self._create_v5_uuid(f'{package.id_} - header description')
            )
        self._add_attribute(attribute, package.id_)

    def _parse_package_context(self, package: STIXPackage,
                               object_courses_of_action: Optional[dict] = None):
        """Convert the context objects a package carries next to its content.

        Campaigns are `campaign-name` attributes. Threat actors are galaxies.
        Courses of action and TTPs are galaxies or MISP objects, and the
        export writes both kinds alike, referenced from the Incident the same
        way: a TTP is told by the title the export gives it, a Course of
        Action by what it carries - the fields a cluster has none of, or the
        timestamp of the object the Incident took it with.

        :param package: the package the context objects are written on
        :param object_courses_of_action: the timestamp of each Course of
            Action the Incident took stamped with the one of a MISP object,
            by uuid
        """
        object_courses_of_action = object_courses_of_action or {}
        if package.campaigns:
            for campaign in package.campaigns:
                self._parse_campaign(campaign)
        if package.courses_of_action:
            for course_of_action in package.courses_of_action:
                coa_uuid = self._extract_uuid(course_of_action.id_)
                if self._is_course_of_action_object(
                        course_of_action, coa_uuid, object_courses_of_action):
                    self._parse_course_of_action(
                        course_of_action,
                        object_courses_of_action.get(coa_uuid)
                    )
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
        self.__unread_journal_entries = 0

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

    def _parse_attack_pattern_object(self, attack_pattern: AttackPattern,
                                     ttp_id: str,
                                     timestamp: Optional[int] = None,
                                     related_weaknesses: tuple = (),
                                     comment: Optional[str] = None):
        """Convert the attack pattern an `attack-pattern` object was exported
        as: its id and name, its descriptions, and the related weaknesses
        its TTP carries as Exploit Targets.

        :param attack_pattern: the attack pattern the TTP carries
        :param ttp_id: the id of the TTP, which the object reads its uuid off
        :param timestamp: the timestamp of the TTP
        :param related_weaknesses: the `related-weakness` attributes read off
            the Exploit Targets of the TTP
        :param comment: the comment read off the TTP description
        """
        attributes = []
        for key, relation in self._mapping.attack_pattern_object_mapping().items():
            value = getattr(attack_pattern, key)
            if value:
                if not isinstance(value, str):
                    value = value.value
                # The export writes `id` the STIX 1 way, `CAPEC-9`; MISP's is
                # the bare number, as the STIX 2 import returns it too
                if relation == 'id' and value.startswith('CAPEC-'):
                    value = value[len('CAPEC-'):]
                attributes.append({'object_relation': relation, 'value': value})
        attributes.extend(self._read_attack_pattern_descriptions(attack_pattern))
        attributes.extend(related_weaknesses)
        if attributes:
            attack_pattern_object = MISPObject('attack-pattern')
            if comment is not None:
                attack_pattern_object.comment = comment
            self._sanitise_object_uuid(attack_pattern_object, ttp_id)
            if timestamp is not None:
                attack_pattern_object.timestamp = timestamp
            for attribute in attributes:
                self._add_object_attribute(
                    attack_pattern_object, attack_pattern_object.uuid,
                    attribute
                )
            self.misp_event.add_object(attack_pattern_object)

    def _read_attack_pattern_descriptions(
            self, attack_pattern: AttackPattern) -> Iterator[dict]:
        """Read the descriptions of an attack pattern: the one tagged with
        a relation is that relation, the untagged one the summary - whichever
        ordinality it takes, since a summary is not always there to come
        first.

        :param attack_pattern: the attack pattern
        :return: the attributes, one per description carrying a value
        """
        described = self._mapping.attack_pattern_description_relations()
        for description in attack_pattern.descriptions or ():
            if not description.value:
                continue
            relation = description.structuring_format
            yield {
                'object_relation': relation if relation in described else 'summary',
                'value': description.value
            }

    def _read_related_weaknesses(self, ttp: TTP) -> Iterator[dict]:
        """Read the weaknesses an attack pattern's TTP carries as Exploit
        Targets, each written under the uuid of the attribute it holds.

        :param ttp: the TTP carrying an attack pattern
        :return: the `related-weakness` attributes
        """
        if ttp.exploit_targets is None:
            return
        for related_exploit_target in ttp.exploit_targets.exploit_target or ():
            exploit_target = related_exploit_target.item
            weaknesses = [
                weakness.cwe_id for weakness in exploit_target.weaknesses or ()
                if weakness.cwe_id
            ]
            for cwe_id in weaknesses:
                attribute = {'object_relation': 'related-weakness', 'value': cwe_id}
                # One Exploit Target, one weakness: several would share a uuid
                if len(weaknesses) == 1 and exploit_target.id_:
                    attribute.update(
                        self._sanitise_attribute_uuid(exploit_target.id_)
                    )
                yield attribute

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
        written into, or off the TTP's own for an attack pattern, the
        timestamp off the TTP. The tags reach a record that takes them - a
        `target-*` attribute, a `vulnerability` attribute carrying its id
        alone - and the ones that land on a MISP object
        instead come back on the event if they are galaxy clusters, warned
        about if they are not.

        :param ttp: the TTP, titled `(MISP Attribute)` or `(MISP Object)`
        """
        # The title is what tells the two kinds apart here: the Related TTP
        # is named with the object name or the attribute type, `vulnerability`
        # either way
        is_object = (ttp.title or '').endswith(_MISP_OBJECT_TITLE_SUFFIX)
        tags = tuple(self._read_markings(ttp.handling))
        timestamp = (
            self._timestamp_from_date(ttp.timestamp) if ttp.timestamp else None
        )
        converted = False
        # The weaknesses an attack pattern's TTP carries are its related
        # weaknesses, not `weakness` objects of their own
        attack_patterns = ttp.behavior.attack_patterns if ttp.behavior else None
        if attack_patterns:
            related_weaknesses = tuple(self._read_related_weaknesses(ttp))
            comment = self._read_comment(ttp.description)
            for attack_pattern in attack_patterns:
                self._parse_attack_pattern_object(
                    attack_pattern, ttp.id_, timestamp, related_weaknesses,
                    comment
                )
                self._read_object_markings(tags)
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
                            vulnerability, ttp.id_, comment, tags, timestamp,
                            is_object
                        )
                    converted = True
                if exploit_target.item.weaknesses and not attack_patterns:
                    for weakness in exploit_target.item.weaknesses:
                        self._parse_weakness_object(
                            weakness, ttp.id_, comment, tags, timestamp
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
            comment: Optional[str] = None, tags: tuple = (),
            timestamp: Optional[int] = None, is_object: bool = False):
        """Convert the vulnerability a TTP carries: a `vulnerability`
        attribute where it holds its id alone and the TTP is not titled as a
        MISP object's, a `vulnerability` object otherwise.

        :param vulnerability: the vulnerability
        :param ttp_id: the id of the TTP carrying it, which the record reads
            its uuid off
        :param comment: the comment read off the Exploit Target
        :param tags: the tags read off the TTP handling
        :param timestamp: the timestamp of the TTP
        :param is_object: whether the TTP is titled `(MISP Object)` - an object
            holding its id alone is still an object
        """
        attributes = []
        for key, mapping in self._mapping.vulnerability_object_mapping().items():
            # A summary past the first is one more description
            values = (
                vulnerability.descriptions or () if key == 'description'
                else (getattr(vulnerability, key),)
            )
            for value in values:
                if value:
                    attribute_type, relation = mapping
                    attributes.append(
                        {
                            'type': attribute_type, 'object_relation': relation,
                            'value': value if isinstance(value, str) else value.value
                        }
                    )
        if vulnerability.cvss_score and vulnerability.cvss_score.overall_score:
            attributes.append(
                {
                    'type': 'float', 'object_relation': 'cvss-score',
                    'value': vulnerability.cvss_score.overall_score
                }
            )
        for reference in vulnerability.references or ():
            attributes.append(
                {
                    'type': 'link', 'object_relation': 'references',
                    'value': reference
                }
            )
        if attributes:
            if (not is_object and len(attributes) == 1
                    and attributes[0]['object_relation'] == 'id'):
                attributes = {
                    **attributes[0],
                    **self._sanitise_attribute_uuid(ttp_id, comment)
                }
                if timestamp is not None:
                    attributes['timestamp'] = timestamp
                if tags:
                    attributes['Tag'] = list(tags)
                self._add_attribute(attributes, ttp_id)
            else:
                vulnerability_object = MISPObject('vulnerability')
                if comment is not None:
                    vulnerability_object.comment = comment
                self._sanitise_object_uuid(vulnerability_object, ttp_id)
                if timestamp is not None:
                    vulnerability_object.timestamp = timestamp
                self._read_object_markings(tags)
                for attribute in attributes:
                    self._add_object_attribute(
                        vulnerability_object, vulnerability_object.uuid,
                        attribute
                    )
                self.misp_event.add_object(vulnerability_object)

    def _parse_weakness_object(
            self, weakness: Weakness, ttp_id: str,
            comment: Optional[str] = None, tags: tuple = (),
            timestamp: Optional[int] = None):
        attributes = []
        for key, relation in self._mapping.weakness_object_mapping().items():
            value = getattr(weakness, key)
            if value:
                attributes.append(
                    (relation, value if isinstance(value, str) else value.value)
                )
        if attributes:
            weakness_object = MISPObject('weakness')
            if comment is not None:
                weakness_object.comment = comment
            self._sanitise_object_uuid(weakness_object, ttp_id)
            if timestamp is not None:
                weakness_object.timestamp = timestamp
            self._read_object_markings(tags)
            for relation, value in attributes:
                self._add_object_attribute(
                    weakness_object, weakness_object.uuid,
                    {'object_relation': relation, 'value': value}
                )
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

        The comment comes back with it: the export writes it as the
        Observable's description, and writes none when the attribute has no
        comment. The tags do not - a CybOX Observable has no room for a
        marking.

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
        comment = self._read_comment(observable.description)
        if comment is not None:
            misp_attribute['comment'] = comment
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
                    if self._is_link(properties, attribute_type, misp_attribute):
                        attribute_type = 'link'
                    self._handle_attribute_case(
                        attribute_type, attribute_value, compl_data,
                        misp_attribute, stix_object_id
                    )
                else:
                    self._handle_attribute_yield(
                        attribute_type, attribute_value, compl_data,
                        misp_attribute, stix_object_id, to_ids
                    )
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

    def _handle_attribute_yield(
            self, name: Optional[str], attributes, compl_data,
            misp_attribute: dict, stix_object_id: str, to_ids: bool):
        """Read an Attribute Observable back as the MISP attribute it was
        exported from, where the handler reading its CybOX object yields the
        attributes of an object.

        That the carrier held exactly one MISP attribute is a property of the
        call path, not of the CybOX shape - the same shape reaches
        `_parse_observable_object` from an object export - so the rule lives
        here rather than in the handlers, which the External parser shares. It
        is written as a rule, not a table of what reduces: a yield of one
        attribute is that attribute, whose type is the MISP attribute type;
        a yield of several reduces only where a composite MISP type spells
        exactly those relations. Anything else lands as the object it reads
        as, carrying what the attribute carried, and a warning says so - a
        shape our export never writes, so a hand-crafted document wearing the
        `misp:tool` label. A yield carrying complementary data to act on is
        never reduced: `_handle_attribute_case` would drop it.

        The routing that brings a carrier here - the relationship naming a
        MISP category, `_parse_indicator` / `_parse_observable` - is an exact,
        case-sensitive match, and no MISP category is also an object template
        name: a new one that were would see an object flattened here.

        :param name: the object template name the handler returned
        :param attributes: the attributes, as the handlers return them
        :param compl_data: the complementary data the handler returned
        :param misp_attribute: the attribute context the caller read - the
            uuid, the category, the comment, the tags, the timestamp
        :param stix_object_id: the id of the Indicator or the Observable
        :param to_ids: the `to_ids` flag the carrier was written with
        """
        if not name:
            # Nothing to name an object with: recorded by the object branch
            self._handle_object_case(
                name, attributes, compl_data,
                object_uuid=misp_attribute.get('uuid')
            )
            return
        if not attributes:
            # An object holding no attribute is no record: the document would
            # be one record short with nothing saying so
            self._empty_yield_error(name, stix_object_id)
            return
        if not isinstance(compl_data, dict):
            attribute = self._attribute_from_yield(name, attributes)
            if attribute is not None:
                self._add_attribute(
                    {**attribute, **misp_attribute}, stix_object_id
                )
                return
        self._unread_attribute_warning(name, stix_object_id)
        self._read_object_markings(misp_attribute.get('Tag', ()))
        # The comment is read already: handed over as the description, it is
        # guarded against the template description alone
        self._handle_object_case(
            name, attributes, compl_data, to_ids=to_ids,
            object_uuid=misp_attribute.get('uuid'),
            description=misp_attribute.get('comment'),
            timestamp=misp_attribute.get('timestamp')
        )

    @staticmethod
    def _attribute_from_yield(name: str, attributes) -> Optional[dict]:
        """Reduce the attributes of an object yield to the one MISP attribute
        they spell.

        :param name: the object template name
        :param attributes: the attributes, as the handlers return them
        :return: the attribute, None when the yield spells none
        """
        if len(attributes) == 1:
            return {
                key: value for key, value in attributes[0].items()
                if key != 'object_relation'
            }
        relations = {
            attribute['object_relation']: attribute['value']
            for attribute in attributes
        }
        if name == 'registry-key' and len(attributes) == len(relations) == 2:
            if set(relations) == {'key', 'data'}:
                return {
                    'type': 'regkey|value',
                    'value': f"{relations['key']}|{relations['data']}"
                }
        return None

    # Parse STIX object that we know will give MISP objects
    def _parse_misp_object_indicator(self, indicator: Indicator):
        """Convert the Indicator a `to_ids` MISP object was exported as.

        The comment comes back through the object template: the export writes
        it as the description and falls back to the template's own
        description, which every MISP object carries, when the object has no
        comment of its own. The description travels raw, and the template it
        is told from is the one of the object the content builds - the name
        here only names the compositions. The handling holds the tags of every
        attribute the object held merged into one set, and a MISP object takes
        no tag: its galaxy clusters come back on the event, and the warning
        records the rest, dropped.

        :param indicator: the Related Indicator the Incident carries
        """
        name = self._define_name(indicator.item.observable, indicator.relationship)
        self._read_object_markings(self._read_markings(indicator.item.handling))
        self._fill_misp_object(
            indicator.item, name, to_ids=True,
            description=indicator.item.description,
            title=indicator.item.title
        )

    def _parse_misp_object_observable(self, observable: Observable):
        name = self._define_name(observable.item, observable.relationship)
        try:
            # The export titles an object Observable only where its CybOX
            # type does not name the template, and describes it only with the
            # object's comment
            self._fill_misp_object(
                observable.item, name,
                description=observable.item.description,
                title=observable.item.title
            )
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
            # The Indicator carries the object's timestamp, a plain Observable
            # none: the object takes none rather than one the wire never gave
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            timestamp = item.timestamp if to_ids else None
            self._parse_observable_object(
                properties, to_ids, self._sanitise_uuid(item.id_), item.id_,
                name=name, description=description, title=title,
                timestamp=(
                    self._timestamp_from_date(timestamp) if timestamp else None
                )
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
        template_types = _template_attribute_types(misp_object.name)
        for observable in observables:
            properties = observable.object_.properties
            if properties._XSI_TYPE == 'CustomObjectType' and properties.custom_name is None:
                self._handle_custom_member(
                    misp_object, observable, template_types, to_ids
                )
                continue
            try:
                attribute = self._handle_attribute_type(properties)
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                continue
            attribute_type, attribute_value, relation = attribute
            if attribute_type == 'hostname' and relation not in template_types:
                # `host` is the `url` relation: every other template names a
                # hostname its own way
                relation = next(
                    (
                        name for name, template_type in template_types.items()
                        if template_type == 'hostname'
                    ),
                    relation
                )
            filename = self._filename_residue(relation)
            if filename is not None:
                # In an object the two halves are two relations, the hash
                # naming its own the way every hash read from a composition
                # does
                self._add_filename_relation(misp_object, filename, to_ids)
                relation = attribute_type
            misp_attribute = {
                'type': attribute_type, 'value': attribute_value,
                'object_relation': relation, 'to_ids': to_ids
            }
            feature = self._cybox_object_feature(observable)
            if feature is not None and feature.endswith('Port'):
                # `srcPort` / `dstPort`: a bare `Port` has no prefix to read
                prefix = feature[:-len('Port')]
                if prefix:
                    misp_attribute['object_relation'] = f'{prefix}-{relation}'
            if observable.id_:
                # The export writes each member with the attribute's uuid
                misp_attribute.update(
                    self._sanitise_attribute_uuid(observable.id_)
                )
            self._add_object_attribute(
                misp_object, misp_object.uuid, misp_attribute
            )
        return misp_object

    def _handle_custom_member(self, misp_object, observable,
                              template_types: dict, to_ids: bool):
        """Read the nameless `Custom` member a composition carries a relation
        it has no member of its own for as: one property named with the
        relation, typed through the template as a property bag is, under the
        uuid the member carries.

        :param misp_object: the object the composition builds
        :param observable: the member
        :param template_types: the attribute types the template defines
        :param to_ids: the `to_ids` flag the composition was written with
        """
        properties = observable.object_.properties
        attributes = list(
            self._read_property_bag(
                properties.custom_properties, template_types,
                misp_object.name, getattr(properties.parent, 'id_', None)
            )
        )
        for attribute_type, value, relation in attributes:
            misp_attribute = {
                'type': attribute_type, 'value': value,
                'object_relation': relation, 'to_ids': to_ids
            }
            # One member, one attribute: several properties would share a uuid
            if len(attributes) == 1 and observable.id_:
                misp_attribute.update(
                    self._sanitise_attribute_uuid(observable.id_)
                )
            self._add_object_attribute(
                misp_object, misp_object.uuid, misp_attribute
            )

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
                misp_attribute = {
                    'type': attribute_type, 'value': attribute_value,
                    'object_relation': relation, 'to_ids': to_ids,
                    'data': compl_data
                }
                if compl_data and observable.id_:
                    # A member carrying data is an Observable of its own,
                    # written with the attribute's uuid - the File member
                    # carries the object's
                    misp_attribute.update(
                        self._sanitise_attribute_uuid(observable.id_)
                    )
                self._add_object_attribute(
                    misp_object, misp_object.uuid, misp_attribute
                )
            else:
                for attribute in attribute_value:
                    attribute['to_ids'] = to_ids
                    self._add_object_attribute(
                        misp_object, misp_object.uuid, attribute
                    )
        return misp_object

    # Create a MISP attribute and add it in its MISP object
    def _parse_observable_object(self, properties, to_ids, uuid, object_id,
                                 name=None, description=None, title=None,
                                 timestamp=None):
        attribute_type, attribute_value, compl_data = self._handle_object_type(
            properties, title
        )
        if isinstance(attribute_value, (str, int)):
            attribute = {'to_ids': to_ids, 'uuid': uuid}
            if timestamp is not None:
                attribute['timestamp'] = timestamp
            # A handler reading its CybOX type as a single attribute - a
            # one-field `DNSRecord`, a nameless `Custom` - names no template
            # to tell the description from a comment: the name the Observable
            # carries is the only one there is
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
                object_uuid=uuid, description=description, title=title,
                timestamp=timestamp
            )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _is_link(properties, attribute_type: str, misp_attribute: dict) -> bool:
        """Tell the `link` a URI object read as a `url` was exported from.

        The wire is the same for both, and pymisp drops a category invalid for
        the type silently: the `url` read under a category only a `link` takes
        came back in `Network activity`. Under a category both take, the two
        cannot be told apart and the `url` stands.

        :param properties: the CybOX object properties
        :param attribute_type: the MISP type the properties read as
        :param misp_attribute: the attribute so far, carrying the category the
            relationship or the Record Title named
        :return: True when the attribute can only have been a `link`
        """
        return (
            attribute_type == 'url' and
            properties._XSI_TYPE == 'URIObjectType' and
            misp_attribute.get('category') in _LINK_ONLY_CATEGORIES
        )

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

    def _handle_object_type(self, properties, title: Optional[str]) -> tuple:
        """Read the content of the CybOX object a MISP object was exported
        as, through the template the Record Title names where the CybOX type
        does not name one.

        A `credential` and a `user-account` with no unix or windows account
        type are both a `UserAccount`, and the handler reads the attributes
        through its own template: the title picks it, before anything is read.
        A `UserAccount` titled with no template name is a `user-account`.

        The content is never reduced to the single attribute the attribute
        path reads it as: the Incident relates a MISP object under its
        meta-category, which no MISP category is, so the kind is on the wire
        and an object comes back as an object whatever it holds - one
        attribute, or a filename and a hash a composite type would spell.

        :param properties: the CybOX object properties
        :param title: the Record Title, where the shape carries one
        :return: what the handler the CybOX type, or the title, picks returns
        """
        if properties._XSI_TYPE == 'UserAccountObjectType':
            if self._object_name_from_title(title) == 'credential':
                return self._handle_credential(properties)
        return self._read_cybox_object(properties)

    @staticmethod
    def _object_name_from_title(title: Optional[str]) -> Optional[str]:
        """Read the object template name off the `{meta-category}: {name}
        (MISP Object)` Record Title.

        :param title: the Indicator or Observable title
        :return: the template name, None when the title names none
        """
        if not title or not title.endswith(_MISP_OBJECT_TITLE_SUFFIX):
            return None
        _, _, name = title[:-len(_MISP_OBJECT_TITLE_SUFFIX)].partition(': ')
        return name or None

    def _handle_regkey(self, properties: WinRegistryKey) -> tuple:
        """Read a registry key, and the references it makes to the
        `registry-key-value` objects the export writes as their own `Custom`
        Observables, pointed at by a Related_Object each.

        The External parser reads the Related_Objects of every CybOX object
        on its own, so the shared handler does not.

        :param properties: the registry key properties
        :return: what the shared handler returns, the references handed back
            as the complementary data: they are applied once the whole
            package is parsed
        """
        name, attributes, compl_data = super()._handle_regkey(properties)
        references = [
            {
                'idref': self._sanitise_uuid(related.idref),
                'relationship': self._related_object_relationship(related)
            }
            for related in properties.parent.related_objects or ()
            if related.idref is not None
        ]
        if references:
            compl_data = {'references': references}
        return name, attributes, compl_data

    @staticmethod
    def _related_object_relationship(related: RelatedObject) -> str:
        # `contains` is written as the vocabulary term, any other relationship
        # verbatim as a free-text term - one spelled `Contains` included
        relationship = related.relationship
        if relationship is None or not relationship.value:
            return 'related-to'
        if isinstance(relationship, ObjectRelationship):
            if relationship.value == 'Contains':
                return 'contains'
        return relationship.value

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

    @staticmethod
    def _cybox_object_feature(observable: Observable) -> Optional[str]:
        """Read the feature the export writes into the id of the CybOX object
        an Observable holds, `{org}:{feature}-{uuid}` - the Observable's own
        id is `{org}:Observable-{uuid}` whatever it holds.

        :param observable: the Observable
        :return: the feature, None where the CybOX object carries no id of
            that shape
        """
        cybox_object = getattr(observable, 'object_', None)
        object_id = getattr(cybox_object, 'id_', None)
        if not object_id or ':' not in object_id or '-' not in object_id:
            return None
        return object_id.split(':', 1)[1].split('-', 1)[0]

    def _define_name(self, observable: Observable, relationship) -> Optional[str]:
        """Name the MISP object an Observable came from.

        Only an observable composition needs one: the export writes the object
        name into the Observable id it gives the composition, and a simple
        Observable takes its name from the CybOX properties themselves - or
        from the Record Title where the CybOX type names no single template -
        in `_handle_object_type`.

        :param observable: the Observable the MISP object was exported as
        :param relationship: the MISP meta-category the export wrote
        :return: the object template name, None when the Observable names none
        """
        # The CybOX type sits on the id of the CybOX object the Observable
        # holds, never on the Observable's own
        feature = self._cybox_object_feature(observable)
        if relationship == "file":
            return "registry-key" if feature == "WindowsRegistryKey" else "file"
        if feature == "Custom":
            return getattr(observable.object_.properties, 'custom_name', None)
        observable_id = observable.id_
        # Whatever the meta-category: the export names every composition the
        # same way, and only the composition branch below uses the name
        if "ObservableComposition" in observable_id:
            return observable_id.split("_")[0].split(":")[1]

    def _is_course_of_action_object(
            self, course_of_action: CourseOfAction, coa_uuid: str,
            object_courses_of_action: dict) -> bool:
        """Tell the Course of Action a `course-of-action` object was exported
        as from the one a galaxy cluster was.

        A cluster is written as a title and a description, and taken by the
        Incident through a bare reference: a field beyond those two, or a
        reference stamped with the object's timestamp, is the object's.

        :param course_of_action: the Course of Action the package carries
        :param coa_uuid: the uuid its id carries
        :param object_courses_of_action: the timestamp of each Course of
            Action the Incident took stamped with the one of a MISP object,
            by uuid
        :return: whether the Course of Action is a MISP object
        """
        if coa_uuid in object_courses_of_action:
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

    def _empty_yield_error(self, name: str, object_id: str):
        self._add_error(
            f'Unable to convert the STIX object with id {object_id}: '
            f'nothing to fill a MISP {name} object with'
        )

    def _unread_attribute_warning(self, name: str, object_id: str):
        # Unreachable from our own export, every attribute of which reduces
        self._add_warning(
            f'Unable to read the STIX object with id {object_id} back as a '
            f'MISP attribute: converted as a {name} object.'
        )

    def _unnamed_composition_warning(self, object_id: str):
        self._add_warning(
            f'Unable to define the MISP object name of the Observable '
            f'composition with id {object_id}: converted as a '
            f'{_UNKNOWN_TEMPLATE_NAME} object.'
        )

    def _unread_journal_entries_warning(self, count: int):
        # Once per document with the count, the entries not quoted: they are
        # free text, and a legacy journal would spend the warnings cap on
        # itself. Our export writes none of them
        entries = 'entry' if count == 1 else 'entries'
        self._add_warning(
            f'{count} Incident journal {entries} matching no grammar the MISP '
            'export writes: not read.'
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
