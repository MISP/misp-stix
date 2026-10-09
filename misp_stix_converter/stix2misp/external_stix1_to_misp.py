#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .importparser import ExternalSTIXtoMISPParser
from .stix1_mapping import ExternalSTIX1toMISPMapping
from .stix1_to_misp import StixObjectTypeError, STIX1toMISPParser
from collections import defaultdict
from contextlib import contextmanager
from cybox.core import Object, Observable
from pymisp import MISPEvent
from stix.campaign import Campaign
from stix.core import STIXPackage
from stix.exploit_target import ExploitTarget
from stix.incident import Incident
from stix.indicator import Indicator
from stix.report import Report
from stix.threat_actor import ThreatActor
from stix.ttp import TTP
from typing import Iterable, Iterator, Optional, Union

class ExternalSTIX1toMISPParser(STIX1toMISPParser, ExternalSTIXtoMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = ExternalSTIX1toMISPMapping

    def parse_stix_package(self, cluster_distribution: Optional[int] = 0,
                           cluster_sharing_group_id: Optional[int] = None,
                           organisation_uuid: Optional[str] = None, **kwargs):
        self._reset_bundle_state()
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
        for container, header, comment in self._containers(self.stix_package):
            self._parse_header(header, container.id_, comment)
            self._parse_content(container)
        if self.dns_objects:
            self._parse_dns_objects()
        for kind, source_id, idref in self.__indicator_references:
            if idref not in self.__read_indicator_ids:
                self._unread_related_indicator_warning(kind, source_id, idref)
        self._set_distribution()
        self._apply_object_references()
        self._apply_event_galaxies()
        self._refuse_empty_event()

    def _reset_bundle_state(self):
        super()._reset_bundle_state()
        # The DNS bookkeeping is only turned into MISP content once the whole
        # package is parsed, so a second package inheriting it gets an event
        # carrying the passive DNS records of the first one
        self.__dns_objects = defaultdict(dict)
        self.__dns_ips = []
        # Which Indicator a related one given by reference names is only
        # known once the whole package is read
        self.__indicator_references = []
        self.__read_indicator_ids = set()

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

    def _parse_records_from_ttp(self, ttp: TTP, galaxies: set) -> list:
        """Read the records a TTP builds, none of them added yet: the galaxy
        tags they all carry are only known once the whole TTP is read.

        :param ttp: the TTP
        :param galaxies: the galaxy tags of the TTP, which the vulnerabilities
            it targets by title only add to
        :return: the records - an attribute as pymisp takes it, an object as
            the Observable it is read from and the read
        """
        records = []
        infrastructure = getattr(ttp.resources, 'infrastructure', None)
        if infrastructure is not None and infrastructure.observable_characterization:
            observables = infrastructure.observable_characterization
            if observables.observables:
                for observable in observables.observables:
                    if not self._has_properties(observable):
                        continue
                    properties = observable.object_.properties
                    try:
                        read = self._read_record(
                            properties, title=observable.title
                        )
                    except StixObjectTypeError as xsi_type:
                        self._stix_object_type_error(xsi_type, ttp.id_)
                        continue
                    attribute_type, attribute_value, compl_data = read
                    if attribute_value is None:
                        self._unfilled_record_error(attribute_type, ttp.id_)
                        continue
                    if self._is_object_read(attribute_value):
                        records.append((observable, read))
                    elif isinstance(attribute_value, list):
                        records.extend(
                            {'type': attribute_type, 'value': value, 'to_ids': False}
                            for value in attribute_value
                        )
                    else:
                        records.append(
                            {
                                'type': attribute_type,
                                'value': attribute_value, 'to_ids': False,
                                **self._file_content(
                                    attribute_type, compl_data
                                )
                            }
                        )
        for exploit_target in self._inline_items(ttp.exploit_targets):
            records.extend(self._read_exploit_target(exploit_target, galaxies))
        return records

    def _read_exploit_target(self, exploit_target: ExploitTarget,
                             galaxies: set) -> list:
        """Read the records an Exploit Target builds - one a TTP holds or
        one the package gives at top level - none of them added yet.

        A vulnerability with a CVE id is a `vulnerability` attribute, one
        with a title alone a galaxy tag, and a weakness with a CWE id a
        `weakness` attribute: the Exploit Target's title is the comment of
        both, and a `text` attribute where there is neither. Each description,
        and each CCE id and description of a configuration, is a `text`
        attribute, a value repeated under one heading read once. The Courses
        of Action it holds are records of their own, not read here. An
        Exploit Target given by reference alone holds nothing: it is read
        where the package defines it.

        :param exploit_target: the Exploit Target
        :param galaxies: the galaxy tags of the construct holding the
            vulnerabilities, which the ones targeted by title only add to
        :return: the attributes, as pymisp takes them
        """
        records = []
        for vulnerability in exploit_target.vulnerabilities or ():
            if vulnerability.cve_id:
                records.append(
                    {'type': 'vulnerability', 'value': vulnerability.cve_id}
                )
            elif vulnerability.title:
                galaxies.update(
                    self._resolve_galaxy(vulnerability.title, 'vulnerability')
                )
        records.extend(
            {'type': 'weakness', 'value': weakness.cwe_id}
            for weakness in exploit_target.weaknesses or ()
            if weakness.cwe_id
        )
        texts = []
        if exploit_target.title:
            if records:
                for record in records:
                    record['comment'] = exploit_target.title
            else:
                texts.append(
                    (exploit_target.title, 'STIX Exploit Target Title')
                )
        texts.extend(
            (self._value(description), 'STIX Exploit Target Description')
            for description in exploit_target.descriptions or ()
        )
        for configuration in exploit_target.configuration or ():
            texts.append(
                (configuration.cce_id, 'STIX Exploit Target Configuration')
            )
            texts.extend(
                (self._value(description), 'STIX Exploit Target Configuration')
                for description in configuration.descriptions or ()
            )
        records.extend(
            {'type': 'text', 'value': value, 'comment': comment}
            for value, comment in dict.fromkeys(texts) if value
        )
        return records

    def _parse_content(self, container: Union[STIXPackage, Report]):
        """Convert the constructs a package or a Report holds.

        A Report mostly names the package's constructs by reference alone:
        those are converted where the package gives them.

        :param container: the package or the Report
        """
        self._parse_indicators(self._inline_constructs(container.indicators))
        self._parse_observables(self._inline_constructs(container.observables))
        # The TTPs sit in a wrapper, absent where there are none
        self._parse_ttps(self._inline_constructs(getattr(container.ttps, 'ttp', None)))
        self._parse_courses_of_action(
            self._inline_constructs(container.courses_of_action)
        )
        for threat_actor in self._inline_constructs(container.threat_actors):
            with self._record_boundary('Threat Actor', threat_actor.id_):
                self._parse_threat_actor(threat_actor)
        for incident in self._inline_constructs(container.incidents):
            with self._record_boundary('Incident', incident.id_):
                self._parse_incident(incident)
        for exploit_target in self._inline_constructs(container.exploit_targets):
            with self._record_boundary('Exploit Target', exploit_target.id_):
                self._parse_exploit_target(exploit_target)
        for campaign in self._inline_constructs(container.campaigns):
            with self._record_boundary('Campaign', campaign.id_):
                self._parse_campaign(campaign)

    def _parse_campaign(self, campaign: Campaign):
        """Convert a Campaign into a `campaign-name` attribute per name it
        holds, each carrying the timestamp, the description as its comment
        and the handling as tags.

        A Campaign naming nothing gives one from its title, and one with no
        title either has no value to give: the warning records it. A
        third-party title is no Record Title, so pymisp's default category
        stands. Nothing else the Campaign holds is read.

        :param campaign: the Campaign
        """
        names = [
            name for name in map(self._value, campaign.names or ()) if name
        ]
        if not names and campaign.title:
            names.append(campaign.title)
        if not names:
            self._add_warning(
                'Unable to read a campaign-name attribute from the Campaign'
                f'{self._record_origin(campaign.id_)}: no name or title'
            )
            return
        self._add_attributes_from_one_id(
            campaign.id_, [('campaign-name', name) for name in names],
            self._read_campaign_context(campaign)
        )

    def _parse_description(self, stix_object: Union[Indicator, Observable]):
        description = self._value(stix_object.description)
        if description:
            misp_attribute = {'type': 'text', 'value': description}
            # An Indicator carries a timestamp, a CybOX Observable none
            timestamp = getattr(stix_object, 'timestamp', None)
            if timestamp:
                misp_attribute['timestamp'] = self._timestamp_from_date(
                    timestamp
                )
            self._add_attribute(misp_attribute, stix_object.id_)

    def _parse_courses_of_action(self, courses_of_action: Iterable):
        for course_of_action in courses_of_action:
            with self._record_boundary('Course of Action', course_of_action.id_):
                self._parse_course_of_action(course_of_action)

    def _parse_dns_objects(self):
        """Convert the DNS bookkeeping, once the whole package is parsed: a
        URL resolving to an address the package holds is a `passive-dns`
        object, the rest is converted as read.

        Each entry is a record of its own, converted inside its own boundary
        as every record of the package is - named by its uuid, the id it was
        read from being no longer kept.
        """
        for uuid, domain in self.dns_objects['domain'].items():
            with self._record_boundary('Observable', uuid):
                domain_attribute = domain['data']
                ip_reference = domain['related']
                if ip_reference in self.dns_objects['ip']:
                    domain_attribute['object_relation'] = "rrname"
                    ip_address = self.dns_objects['ip'][ip_reference]['value']
                    # Built through the shared object handler, which is where
                    # the guard against what MISP refuses sits
                    self._handle_object_case(
                        'passive-dns',
                        (
                            domain_attribute,
                            {
                                'type': 'text', 'object_relation': 'rdata',
                                'value': ip_address
                            },
                            {
                                'type': 'text', 'object_relation': 'rrtype',
                                'value': "AAAA" if ":" in ip_address else "A"
                            }
                        ),
                        None
                    )
                else:
                    self._add_attribute(domain_attribute)
        for ip, ip_attribute in self.dns_objects['ip'].items():
            if ip not in self.dns_ips:
                with self._record_boundary('Observable', ip):
                    self._add_attribute(ip_attribute)

    def _parse_exploit_target(self, exploit_target: ExploitTarget):
        galaxies = set()
        records = self._read_exploit_target(exploit_target, galaxies)
        self._add_construct_records(exploit_target.id_, records, galaxies)
        self._parse_courses_of_action(
            self._inline_items(exploit_target.potential_coas)
        )

    def _parse_galaxies_from_ttp(self, ttp: TTP):
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    yield from self._parse_galaxy(attack_pattern, 'title', 'attack_pattern')
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    yield from self._parse_galaxy(malware_instance, 'title', 'malware')
        if ttp.resources and ttp.resources.tools:
            for tool in ttp.resources.tools:
                yield from self._parse_galaxy(tool, 'name', 'tool')

    def _parse_header(self, header, construct_id: Optional[str],
                      comment: str):
        """Convert a header: each description is a `text` attribute, as an
        Incident's are, and the handling is the event's tags.

        :param header: the header, None where the construct carries none
        :param construct_id: the id of the construct the header belongs to
        :param comment: the comment of the description attributes
        """
        if header is None:
            return
        descriptions = [
            ('text', value)
            for value in map(self._value, header.descriptions or ())
            if value
        ]
        self._add_attributes_from_one_id(
            construct_id, descriptions, {'comment': comment}
        )
        for handling in header.handling or ():
            for tag in self._parse_marking(handling):
                self.misp_event.add_tag(tag)

    def _parse_incident(self, incident: Incident):
        """Convert an Incident: its descriptions, and the Indicators,
        Observables and TTPs it relates inline.

        Each description is a `text` attribute, as the header's is - and as
        the header's, it takes neither the timestamp nor the handling. A
        related construct given by reference alone is converted where the
        package defines it. Nothing else the Incident holds is read.

        :param incident: the Incident
        """
        descriptions = [
            ('text', value)
            for value in map(self._value, incident.descriptions or ())
            if value
        ]
        self._add_attributes_from_one_id(
            incident.id_, descriptions,
            {'comment': 'STIX Incident Description'}
        )
        self._parse_related_indicators(
            'Incident', incident.id_, incident.related_indicators
        )
        self._parse_observables(
            self._inline_items(incident.related_observables)
        )
        self._parse_ttps(self._inline_items(incident.leveraged_ttps))

    def _parse_indicator(self, indicator: Indicator):
        # Converted before the observable: the rules an Indicator carries are
        # attributes of their own whatever becomes of what it describes - an
        # observable of an unknown type loses itself, not the rules with it
        test_mechanisms = self._parse_test_mechanisms(indicator)
        if hasattr(indicator, 'observable') and indicator.observable:
            observable = indicator.observable
            if self._has_properties(observable):
                properties = observable.object_.properties
                record = self._record_uuid(observable)
                uuid = record['uuid']
                try:
                    attribute_type, attribute_value, compl_data = self._read_record(properties, title=observable.title)
                except StixObjectTypeError as xsi_type:
                    self._stix_object_type_error(xsi_type, indicator.id_)
                    return
                if isinstance(attribute_value, (str, int)):
                    if observable.object_.related_objects:
                        related_objects = observable.object_.related_objects
                        resolving = (
                            attribute_type == "url" and len(related_objects) == 1 and
                            self._value(related_objects[0].relationship) == "Resolved_To"
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
                            {
                                'type': attribute_type,
                                'value': attribute_value, **record
                            }
                        )
                        self.dns_objects['ip'][uuid] = attribute
                        return
                    self._handle_attribute_case(
                        attribute_type, attribute_value, compl_data,
                        attribute, observable.object_.id_,
                        uuid_comment=record.get('comment')
                    )
                elif attribute_value is None:
                    self._unfilled_record_error(attribute_type, indicator.id_)
                else:
                    if self._is_object_read(attribute_value):
                        # it is a list of attributes, so we build an object
                        self._handle_object_case(
                            attribute_type, attribute_value, compl_data,
                            to_ids=True, object_uuid=uuid,
                            test_mechanisms=test_mechanisms,
                            timestamp=(
                                self._timestamp_from_date(indicator.timestamp)
                                if indicator.timestamp else None
                            ),
                            uuid_comment=record.get('comment')
                        )
                        self._record_related_objects(observable.object_, uuid)
                    else:
                        # it is a list of attribute values, so we add single attributes
                        for value in attribute_value:
                            self._add_attribute(
                                {
                                    'type': attribute_type, 'value': value,
                                    'to_ids': True
                                },
                                observable.object_.id_
                            )
            elif hasattr(observable, 'observable_composition') and observable.observable_composition:
                self._parse_observables(observable.observable_composition.observables, to_ids=True)
            else:
                self._parse_description(indicator)

    def _parse_indicators(self, indicators: Iterable[Indicator]):
        for indicator in indicators:
            if indicator.id_:
                self.__read_indicator_ids.add(indicator.id_)
            with self._record_boundary('Indicator', indicator.id_):
                self._parse_indicator(indicator)
            self._parse_related_indicators(
                'Indicator', indicator.id_, indicator.related_indicators
            )

    def _parse_related_indicators(self, kind: str, source_id: Optional[str],
                                  relationships):
        """Convert the Indicators an Indicator or an Incident relates.

        One given inline is read as the package's own are, the Indicators it
        relates in turn included, at every depth: the XML nests them, so no
        chain of them loops back. One given by reference alone is read where
        the package gives it, and one the package gives nowhere is warned.

        :param kind: the kind of STIX construct relating the Indicators
        :param source_id: the id of the construct, None where it carries none
        :param relationships: the related Indicators
        """
        for relationship in relationships or ():
            item = relationship.item
            if item is not None and item.idref is not None:
                self.__indicator_references.append(
                    (kind, source_id, item.idref)
                )
        self._parse_indicators(self._inline_items(relationships))

    def _parse_observables(self, observables: Iterable[Observable],
                           to_ids: bool = False):
        for observable in observables:
            with self._record_boundary('Observable', observable.id_):
                self._parse_observable(observable, to_ids)

    def _parse_observable(self, observable: Observable, to_ids: bool):
        if self._has_properties(observable):
            observable_object = observable.object_
            properties = observable_object.properties
            try:
                attribute_type, attribute_value, compl_data = self._read_record(properties, title=observable.title)
            except StixObjectTypeError as xsi_type:
                self._stix_object_type_error(xsi_type, observable.id_)
                return
            record = self._record_uuid(observable)
            uuid = record['uuid']
            if isinstance(attribute_value, (str, int)):
                if observable.object_.related_objects:
                    related_objects = observable.object_.related_objects
                    resolving = (
                        attribute_type == "url" and len(related_objects) == 1 and
                        self._value(related_objects[0].relationship) == "Resolved_To"
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
                attribute = {'to_ids': to_ids, 'uuid': uuid}
                if hasattr(observable, 'handling') and observable.handling:
                    attribute['Tag'] = []
                    for handling in observable.handling:
                        attribute['Tag'].extend(self._parse_marking(handling))
                if attribute_type in ('ip-src', 'ip-dst'):
                    attribute.update(
                        {
                            'type': attribute_type,
                            'value': attribute_value, **record
                        }
                    )
                    self.dns_objects['ip'][uuid] = attribute
                    return
                self._handle_attribute_case(
                    attribute_type, attribute_value, compl_data,
                    attribute, observable_object.id_,
                    uuid_comment=record.get('comment')
                )
            elif attribute_value is not None:
                if self._is_object_read(attribute_value):
                    # it is a list of attributes, so we build an object
                    self._handle_object_case(
                        attribute_type, attribute_value, compl_data,
                        to_ids=to_ids, object_uuid=uuid,
                        uuid_comment=record.get('comment')
                    )
                    self._record_related_objects(observable_object, uuid)
                else:
                    # it is a list of attribute values, so we add single attributes
                    for value in attribute_value:
                        self._add_attribute(
                            {
                                'type': attribute_type, 'value': value,
                                'to_ids': to_ids
                            },
                            observable_object.id_
                        )
            else:
                self._unfilled_record_error(attribute_type, observable.id_)
        else:
            self._parse_description(observable)

    def _parse_test_mechanisms(self, indicator: Indicator) -> list:
        """Convert the test mechanisms of an Indicator into attributes.

        The Indicator converts to no record of its own - what its observable
        yields takes the id of the observable - so its uuid goes to the rules,
        as the Internal parser gives it: the first takes it, the rest derive
        theirs from it. A rule attribute carries nothing else the Indicator
        holds.

        :param indicator: the Indicator carrying the test mechanisms
        :return: the uuids of the attributes the rules landed as
        """
        rules, _ = self._read_test_mechanisms(indicator)
        return self._add_attributes_from_one_id(
            indicator.id_, rules, {}, self._repeated_rule_warning
        )

    def _parse_threat_actor(self, threat_actor: ThreatActor):
        if getattr(threat_actor, 'title', None) is not None:
            self.galaxies.update(self._parse_galaxy(threat_actor, 'title', 'threat_actor'))
        elif getattr(threat_actor, 'identity', None) is not None:
            identity = threat_actor.identity
            if getattr(identity, 'name', None) is not None:
                self.galaxies.update(self._resolve_galaxy(identity.name, 'threat_actor'))
            elif hasattr(identity, 'specification') and getattr(identity.specification, 'party_name', None) is not None:
                party_name = identity.specification.party_name
                if getattr(party_name, 'person_names', None) is not None:
                    names = party_name.person_names
                elif getattr(party_name, 'organisation_names', None) is not None:
                    names = party_name.organisation_names
                else:
                    names = ()
                for name in names:
                    value = self._value(next(iter(name.name_elements or ()), None))
                    if value is not None:
                        self.galaxies.update(
                            self._resolve_galaxy(value, 'threat_actor')
                        )

    def _parse_ttp(self, ttp: TTP):
        galaxies = set(self._parse_galaxies_from_ttp(ttp))
        records = self._parse_records_from_ttp(ttp, galaxies)
        self._add_construct_records(ttp.id_, records, galaxies)
        for exploit_target in self._inline_items(ttp.exploit_targets):
            self._parse_courses_of_action(
                self._inline_items(exploit_target.potential_coas)
            )

    def _parse_ttps(self, ttps: Iterable[TTP]):
        for ttp in ttps:
            with self._record_boundary('TTP', ttp.id_):
                self._parse_ttp(ttp)

    def _add_construct_records(self, construct_id: Optional[str],
                               records: list, galaxies: set):
        """Add the records a TTP or an Exploit Target builds, each carrying
        the galaxy tags of the construct.

        :param construct_id: the id of the TTP or Exploit Target
        :param records: the records it builds - an attribute as pymisp takes
            it, an object as the Observable it is read from and the read
        :param galaxies: the galaxy tags of the construct
        """
        construct_uuid = None
        if len(records) == 1:
            # The sole record a construct builds is the construct, and takes
            # its uuid - next to the comment an attribute already carries
            record = records[0]
            construct_uuid = self._sanitise_attribute_uuid(
                construct_id,
                record.get('comment') if isinstance(record, dict) else None
            )
        tags = sorted(galaxies)
        added = False
        for record in records:
            if isinstance(record, dict):
                added |= self._add_construct_attribute(
                    construct_id, record, tags, construct_uuid
                )
            else:
                added |= self._add_ttp_object(*record, tags, construct_uuid)
        if not added:
            # Nothing the construct builds carries its galaxies: the event does
            self.galaxies.update(galaxies)

    def _add_construct_attribute(self, construct_id: Optional[str],
                                 attribute: dict, tags: list,
                                 construct_uuid: Optional[dict]) -> bool:
        if construct_uuid is not None:
            attribute.update(construct_uuid)
        if tags:
            attribute['Tag'] = tags
        return self._add_attribute(attribute, construct_id) is not None

    def _add_ttp_object(self, observable: Observable, read: tuple, tags: list,
                        ttp_uuid: Optional[dict]) -> bool:
        # An object it includes - an email's attachment - is no record of the
        # TTP's own, and not counted in telling the sole one: it is built
        # under the object, and carries the galaxies as every record built
        # from the TTP does, MISP having no tag for an object. What the call
        # added is read off the event, the included objects with the one
        # returned
        record_uuid = ttp_uuid or self._record_uuid(observable)
        count = len(self.misp_event.objects)
        # The `to_ids` flag is left false: the infrastructure a TTP uses is
        # no detection
        self._handle_object_case(
            *read, object_uuid=record_uuid['uuid'],
            uuid_comment=record_uuid.get('comment')
        )
        self._record_related_objects(observable.object_, record_uuid['uuid'])
        built = self.misp_event.objects[count:]
        for misp_object in built:
            for attribute in misp_object.attributes:
                for tag in tags:
                    attribute.add_tag(tag)
        return bool(built)

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    def _containers(self, package: STIXPackage) -> Iterator[tuple]:
        """Walk what holds the content of a document, in reading order: the
        package, its Reports, then each package it relates inline in turn.

        Every package the document holds is one event, so a related package
        is read as the document is: a document whose content sits in them or
        in its Reports alone converted to nothing. One given by reference
        alone holds nothing to read.

        :param package: the package
        :return: each package or Report, its header and the comment of the
            attributes its header descriptions convert to
        """
        yield package, package.stix_header, 'STIX Header Description'
        for report in self._inline_constructs(package.reports):
            yield from self._reports(report)
        for related_package in self._inline_items(package.related_packages):
            yield from self._containers(related_package)

    def _reports(self, report: Report) -> Iterator[tuple]:
        yield report, report.header, 'STIX Report Description'
        for related_report in self._inline_items(report.related_reports):
            yield from self._reports(related_report)

    def _get_event_info(self):
        # The first title in reading order: the document's own, then the ones
        # of its Reports and of the packages it relates. Testing the value, not
        # the attribute: a STIX header always carries a `title` field, set to
        # None when absent, so `hasattr` would return the missing title
        # instead of falling through.
        for container, header, _ in self._containers(self.stix_package):
            for title in (getattr(container, 'title', None),
                          getattr(header, 'title', None)):
                if title:
                    return title
        return f"Imported from external STIX {self.stix_version} Package"

    @contextmanager
    def _record_boundary(self, kind: str, record_id: Optional[str]):
        """Hold what converting one record raises to that record.

        A third-party document is free to hold shapes no guard here was
        written for, and what one of them raised escaped
        `parse_stix_package()` with the whole package - every record already
        converted and the diagnostics included. It costs the record it
        happened in, and the Error names the record with the traceback, as
        the STIX 2 import does. What the record added before it failed stays.

        :param kind: the kind of STIX construct the record is read from
        :param record_id: the id of the construct, None where it carries none
        """
        try:
            yield
        except Exception as exception:
            self._add_error(
                f'Error while parsing the {kind}'
                f'{self._record_origin(record_id)}: '
                f'{self._parse_traceback(exception)}'
            )

    def _record_related_objects(self, observable_object: Object, uuid: str):
        # Recorded rather than applied: the objects they point to may not be
        # parsed yet, so they are turned into MISP object references once the
        # whole package is - a related object embedded rather than referenced
        # carries its own id, one carrying neither names nothing to reference
        if not observable_object.related_objects:
            return
        for related_object in observable_object.related_objects:
            if related_object.idref is None:
                continue
            relationship = self._value(related_object.relationship)
            self.references[uuid].append(
                {
                    'idref': self._sanitise_uuid(related_object.idref),
                    'relationship': (
                        relationship.lower().replace('_', '-')
                        if relationship else 'related-to'
                    )
                }
            )

    def _unfilled_record_error(self, name: Optional[str], object_id: str):
        # A handler reading no value names the attribute it would have been,
        # one reading no property of a nameless object names nothing
        if name:
            self._empty_record_error(name, object_id, 'attribute')
        else:
            self._unnamed_object_error(object_id)

    def _unread_related_indicator_warning(
            self, kind: str, source_id: Optional[str], idref: str):
        # An Indicator only a construct the import does not read gives is
        # unread too: the message says no more than what was read
        self._add_warning(
            f'Unable to convert the Indicator with id {idref} the {kind}'
            f'{self._record_origin(source_id)} relates by reference: no '
            'Indicator read from the package carries that id'
        )

    @staticmethod
    def _inline_constructs(constructs) -> Iterator:
        # A construct given by idref alone is converted where the package
        # defines it
        for construct in constructs or ():
            if construct.idref is None:
                yield construct

    @classmethod
    def _inline_items(cls, relationships) -> Iterator:
        # A relationship holding no construct - the schema requires one - has
        # nothing to convert
        yield from cls._inline_constructs(
            relationship.item for relationship in relationships or ()
            if relationship.item is not None
        )
