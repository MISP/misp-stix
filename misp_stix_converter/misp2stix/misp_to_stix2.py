#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from .exportparser import MISPtoSTIXParser
from abc import ABCMeta
from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from pathlib import Path
from pymisp import (
    MISPAttribute, MISPEvent, MISPEventReport, MISPGalaxy, MISPGalaxyCluster,
    MISPNote, MISPObject, MISPOpinion)
from stix2.hashes import check_hash, Hash
from stix2.properties import ListProperty, StringProperty
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Campaign as Campaign_v20,
    CourseOfAction as CourseOfAction_v20, CustomObject as CustomObject_v20,
    Identity as Identity_v20, Indicator as Indicator_v20,
    IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Tool as Tool_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21, CustomObject as CustomObject_v21,
    Identity as Identity_v21, Indicator as Indicator_v21,
    IntrusionSet as IntrusionSet_v21, Location, Malware as Malware_v21, Note,
    ObservedData as ObservedData_v21, Tool as Tool_v21,
    Vulnerability as Vulnerability_v21)
from typing import Generator, Optional, Tuple, Union

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone
    UTC = timezone.utc

_event_report_regex = r'@[!]?\[%s\]\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)'
_label_fields = ('type', 'category', 'to_ids')
_labelled_object_types = ('malware', 'threat-actor', 'tool')
_misp_time_fields = ('first_seen', 'last_seen')
_object_attributes_additional_fields = ('category', 'comment', 'to_ids', 'uuid')
_object_attributes_fields = ('type', 'object_relation', 'value')
_special_characters = (' ', '.')
_stix_time_fields = {
    'indicator': ('valid_from', 'valid_until'),
    'observed-data': ('first_observed', 'last_observed')
}

_MISP_DATA_LAYER = Union[
    dict, MISPAttribute, MISPEventReport, MISPObject
]
_STIX_OBJECT_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21, Campaign_v20, Campaign_v21,
    CourseOfAction_v20, CourseOfAction_v21, CustomObject_v20, CustomObject_v21,
    Identity_v20, Identity_v21, Indicator_v20, Indicator_v21,
    IntrusionSet_v20, IntrusionSet_v21, Location, Malware_v20, Malware_v21,
    Note, ObservedData_v20, ObservedData_v21, Tool_v20, Tool_v21,
    Vulnerability_v20, Vulnerability_v21, dict
]


class InvalidHashValueError(Exception):
    pass


class MISPtoSTIX2Parser(MISPtoSTIXParser, metaclass=ABCMeta):
    def __init__(self, interoperability: bool):
        super().__init__()
        self.__ids: dict = {}
        self.__index = 0
        self.__initiated = False
        self.__interoperability = interoperability
        self._id_parsing_function = {
            'attribute': '_define_stix_object_id',
            'object': '_define_stix_object_id'
        }
        self._markings = {}

    def parse_misp_attribute(self, attribute: Union[MISPAttribute, dict]):
        self._results_handling_function = '_append_SDO_without_refs'
        self._identifier = 'attribute feed'
        if not self.__initiated:
            self._initiate_feed_parsing()
        self._handle_identity_from_feed(attribute.get('Event', {}))
        if 'Attribute' in attribute:
            attribute = attribute['Attribute']
        self._resolve_attribute(attribute)

    def parse_misp_attributes(self, attributes: Union[MISPAttribute, dict]):
        self._results_handling_function = '_append_SDO_without_refs'
        self._identifier = 'attributes collection'
        if not self.__initiated:
            self._initiate_attributes_parsing()
        if 'Attribute' in attributes:
            if 'Galaxy' in attributes:
                self._parse_event_galaxies(attributes['Galaxy'])
            attributes = attributes['Attribute']
        for attribute in attributes:
            self._resolve_attribute(attribute)
        if self._markings:
            for marking in self._markings.values():
                if not marking['used']:
                    self._append_SDO_without_refs(marking['marking'])
                    marking['used'] = True
        if self.__relationships:
            self._handle_relationships()

    def parse_misp_event(self, misp_event: Union[MISPEvent, dict]):
        self._results_handling_function = '_append_SDO'
        if not self.__initiated:
            self._initiate_events_parsing()
        self._parse_misp_event(misp_event)

    def _parse_json_content(self, json_content: dict | list):
        self._results_handling_function = '_append_SDO'
        if 'response' in json_content:
            json_content = json_content['response']
            if isinstance(json_content, list):
                if not self.__initiated:
                    self._initiate_events_parsing()
                for event in json_content:
                    self._parse_misp_event(event)
                    self.__index = len(self.__objects)
            else:
                self.parse_misp_attributes(json_content)
        else:
            if isinstance(json_content, list):
                for content in json_content:
                    if 'Attribute' in content:
                        self.parse_misp_attribute(content)
            else:
                if 'Event' in json_content or 'info' in json_content:
                    self.parse_misp_event(json_content)
                else:
                    self.parse_misp_attributes(json_content)

    def _parse_misp_event(self, misp_event: MISPEvent | dict):
        if 'Event' in misp_event:
            misp_event = misp_event['Event']
        self._misp_event = misp_event
        self._identifier = self._misp_event['uuid']
        self.__event_timestamp = self._handle_event_timestamp()
        self.__object_refs = []
        self.__relationships = []
        self._handle_identity_from_event()
        if self._misp_event.get('EventReport'):
            self._id_parsing_function = {
                'attribute': '_define_stix_object_id_from_attribute',
                'object': '_define_stix_object_id_from_object'
            }
            self._event_report_matching = defaultdict(list)
            self._handle_attributes_and_objects()
            for event_report in self._misp_event['EventReport']:
                note = self._parse_event_report(event_report)
                self._append_SDO(note)
                self._handle_analyst_data(note, event_report)
        else:
            self._id_parsing_function = {
                'attribute': '_define_stix_object_id',
                'object': '_define_stix_object_id'
            }
            self._handle_attributes_and_objects()
        report = self._generate_report_from_event()
        self.__objects.insert(self.__index, report)

    def _define_stix_object_id(
            self, feature: str, misp_object: MISPObject | dict) -> str:
        return f"{feature}--{misp_object['uuid']}"

    def _define_stix_object_id_from_attribute(
            self, feature: str, attribute: MISPAttribute | dict) -> str:
        attribute_uuid = attribute['uuid']
        stix_id = f'{feature}--{attribute_uuid}'
        self._event_report_matching[attribute_uuid].append(stix_id)
        return stix_id

    def _define_stix_object_id_from_object(
            self, feature: str, misp_object: MISPObject | dict) -> str:
        object_uuid = misp_object['uuid']
        stix_id = f'{feature}--{object_uuid}'
        self._event_report_matching[object_uuid].append(stix_id)
        for attribute in misp_object['Attribute']:
            self._event_report_matching[attribute['uuid']].append(stix_id)
        return stix_id

    def _handle_attributes_and_objects(self):
        if self._misp_event.get('Attribute'):
            for attribute in self._misp_event['Attribute']:
                self._resolve_attribute(attribute)
        if self._misp_event.get('Object'):
            self._objects_to_parse = defaultdict(dict)
            self._resolve_objects()
            if self._objects_to_parse:
                self._resolve_objects_to_parse()
                if self._objects_to_parse.get('annotation'):
                    objects_to_parse = self._objects_to_parse['annotation']
                    for misp_object in objects_to_parse.values():
                        to_ids, annotation_object = misp_object
                        custom = (
                            annotation_object.get('ObjectReference') is None or
                            not self._annotates(
                                annotation_object['ObjectReference']
                            )
                        )
                        if custom:
                            self._parse_custom_object(annotation_object)
                        else:
                            self._parse_annotation_object(
                                to_ids, annotation_object
                            )

    def _handle_default_identity(self):
        misp_identity_args = self._mapping.misp_identity_args()
        self.__identity_id = misp_identity_args['id']
        if self.identity_id not in self.unique_ids:
            identity = self._create_identity(misp_identity_args)
            self._append_SDO_without_refs(identity)
            self.__ids[self.identity_id] = self.identity_id

    def _handle_event_timestamp(self) -> datetime:
        event_timestamp = self._misp_event.get('timestamp')
        if event_timestamp is not None:
            return self._datetime_from_timestamp(event_timestamp)
        return datetime.now()

    def _handle_identity_from_event(self) -> str:
        orgc = self._misp_event.get('Orgc', {})
        if any(orgc.get(feature) is None for feature in ('name', 'uuid')):
            if not orgc:
                self._missing_orgc_error()
            else:
                self._missing_orgc_field_error(orgc)
            self._handle_default_identity()
        else:
            self.__identity_id = f"identity--{orgc['uuid']}"
            if self.identity_id not in self.unique_ids:
                self.__ids[self.identity_id] = self.identity_id
                identity = self._create_identity_object(orgc['name'])
                self._append_SDO_without_refs(identity)
                self.__index += 1

    def _handle_identity_from_feed(self, event: dict) -> str:
        if 'Orgc' in event:
            self.__identity_id = f"identity--{event['Orgc']['uuid']}"
            if self.identity_id not in self.unique_ids:
                identity_args = {
                    'type': 'identity', 'identity_class': 'organization',
                    'id': self.identity_id, 'name': event['Orgc']['name']
                }
                identity = self._create_identity(identity_args)
                self._append_SDO_without_refs(identity)
                self.__ids[self.identity_id] = self.identity_id
        else:
            self._handle_default_identity()

    def _initiate_attributes_parsing(self):
        self.__objects = []
        self.__object_refs = []
        self.__relationships = []
        self._handle_default_identity()
        self.__initiated = True

    def _initiate_events_parsing(self):
        self.__objects = []
        self.__index = 0
        self.__initiated = True

    def _initiate_feed_parsing(self):
        self.__objects = []
        self.__initiated = True

    @property
    def bundle(self) -> Union[Bundle_v20, Bundle_v21]:
        """
        Returns a STIX Bundle with the STIX objects converted from MISP.
        Every variable used so far to store objects, IDs, references and so on must
        be then re-initialised so the next MISP content that is converted does not
        concern the Bundle that is generated here.
        """
        self.__ids = {}
        self.__initiated = False
        self._markings = {}
        self.__index = 0
        return self._create_bundle()

    @property
    def event_timestamp(self) -> datetime:
        try:
            return self.__event_timestamp
        except AttributeError:
            event_timestamp = datetime.now()
            self.__event_timestamp = event_timestamp
            return event_timestamp

    @property
    def fetch_stix_objects(self) -> list:
        """
        Fetch the list of STIX objects to be handled outside of this class (like to
        add them in a STIX Bundle).
        Variables like the ones containind STIX objects, references and so on are
        re-initialised, but the list of unique IDs for instance remains the same.
        """
        self.__initiated = False
        return self.__objects

    @property
    def identity_id(self) -> str:
        return self.__identity_id

    @property
    def interoperability(self) -> bool:
        return self.__interoperability

    @property
    def object_refs(self) -> list:
        return self.__object_refs

    def populate_unique_ids(self, unique_ids: dict):
        self.__ids.update(unique_ids)

    @property
    def stix_objects(self) -> list:
        """
        Simply returns the list of STIX objects.
        All variables containing the IDs, STIX objects, references and so on remain
        the same and are not re-initialised.
        """
        return self.__objects

    @property
    def unique_ids(self) -> dict:
        return self.__ids

    ############################################################################
    #                          MAIN PARSING FUNCTIONS                          #
    ############################################################################

    def _append_SDO(self, stix_object):
        self.__objects.append(stix_object)
        self.object_refs.append(stix_object.id)

    def _append_SDO_without_refs(self, stix_object):
        self.__objects.append(stix_object)

    def _generate_report_from_event(self):
        report_args = {
            'name': self._misp_event.get(
                'info',
                f'MISP Event exported to STIX {self._version} with misp-stix.'
            ),
            'created': self.event_timestamp, 'modified': self.event_timestamp,
            'labels': ['Threat-Report','misp:tool="MISP-STIX-Converter"'],
            'created_by_ref': self.identity_id, 'interoperability': True
        }
        markings = self._handle_event_tags_and_galaxies()
        if markings:
            self._handle_markings(report_args, markings)
        if self.__relationships:
            self._handle_relationships()
        if self._markings:
            for marking in self._markings.values():
                if not marking['used']:
                    self._append_SDO_without_refs(marking['marking'])
                    marking['used'] = True
        if self._is_published():
            report_id = f"report--{self._misp_event['uuid']}"
            if not self.object_refs:
                self._handle_empty_object_refs(report_id, self.event_timestamp)
            published = self._datetime_from_timestamp(
                self._misp_event['publish_timestamp']
            )
            report_args.update(
                {
                    'id': report_id, 'type': 'report',
                    'published': published, 'allow_custom': True
                }
            )
            self._handle_analyst_data(report_args)
            report_args['object_refs'] = self.object_refs
            report = self._create_report(report_args)
            return report
        return self._handle_unpublished_report(report_args)

    def _generate_galaxies_catalog(self):
        current_path = Path(os.path.dirname(os.path.realpath(__file__)))
        cti_path = current_path.parent / 'data' / 'cti'
        self._galaxies_catalog = defaultdict(lambda: defaultdict(list))
        self._identities = {}
        for filename in cti_path.glob('*/*.json'):
            with open(filename, 'rt', encoding='utf-8') as f:
                bundle = json.loads(f.read())
            for stix_object in bundle['objects']:
                if stix_object['type'] == 'identity':
                    object_id = stix_object['id']
                    not_unique = (
                        object_id not in self.unique_ids or
                        object_id not in self._identities
                    )
                    if not_unique:
                        self._identities[object_id] = stix_object
                    continue
                if not stix_object.get('name'):
                    continue
                name = stix_object['name']
                object_type = stix_object['type']
                object_id = stix_object['id']
                if object_id not in self._get_object_ids(name, object_type):
                    self._galaxies_catalog[name][object_type].append(
                        stix_object
                    )
                if not stix_object.get('external_references'):
                    continue
                mapping = self._mapping.source_names()
                for reference in stix_object['external_references']:
                    if reference['source_name'] in mapping:
                        ext_id = reference['external_id']
                        object_ids = self._get_object_ids(ext_id, object_type)
                        if object_id not in object_ids:
                            self._galaxies_catalog[ext_id][object_type].append(
                                stix_object
                            )
                        break

    def _get_object_ids(
            self, name: str, object_type: str) -> Generator[None, None, str]:
        return (
            stix_object['id'] for stix_object
            in self._galaxies_catalog[name][object_type]
        )

    def _handle_analyst_data(self, stix_object: _STIX_OBJECT_TYPING,
                             data_layer: _MISP_DATA_LAYER = None):
        if data_layer is None:
            data_layer = self._misp_event
        for note in data_layer.get('Note', []):
            self._handle_note_data(stix_object, note)
        for opinion in data_layer.get('Opinion', []):
            self._handle_opinion_data(stix_object, opinion)

    def _handle_object_analyst_data(self, stix_object: _STIX_OBJECT_TYPING,
                                    misp_object: Union[MISPObject, dict]):
        self._handle_analyst_data(stix_object, misp_object)
        for attribute in misp_object['Attribute']:
            self._handle_analyst_data(stix_object, attribute)

    def _handle_relationships(self):
        for relationship in self.__relationships:
            if relationship.get('undefined_target_ref'):
                target_ref = self._find_target_uuid(
                    relationship.pop('undefined_target_ref')
                )
                if target_ref is None:
                    continue
                relationship['target_ref'] = target_ref
            self._append_SDO(self._create_relationship(relationship))

    def _handle_sightings(self, sightings: list, reference_id: str):
        for sighting in sightings:
            sighting_type = sighting.get('type')
            if sighting_type == '0':
                sighting_args = {
                    'id': f"sighting--{sighting['uuid']}",
                    'type': 'sighting', 'sighting_of_ref': reference_id
                }
                if 'x-misp-' in reference_id:
                    sighting_args['allow_custom'] = True
                if sighting.get('date_sighting', ''):
                    date_sighting = self._datetime_from_timestamp(
                        sighting['date_sighting']
                    )
                    sighting_args.update(
                        {'created': date_sighting, 'modified': date_sighting}
                    )
                if sighting.get('Organisation', {}):
                    sighting_args['where_sighted_refs'] = [
                        self._handle_sighting_identity(
                            sighting['Organisation']['uuid'],
                            sighting['Organisation']['name']
                        )
                    ]
                if sighting.get('source', ''):
                    sighting_args['description'] = sighting['source']
                getattr(self, self._results_handling_function)(
                    self._create_sighting(sighting_args)
                )
            elif sighting_type == '1':
                self._handle_opinion_object(sighting, reference_id)

    def _handle_sighting_identity(self, uuid: str, name: str) -> str:
        identity_id = f'identity--{uuid}'
        if identity_id not in self.unique_ids:
            self._handle_identity(identity_id, name)
        return identity_id

    def _parse_event_report_references(
            self, event_report: Union[MISPEventReport, dict]):
        references = {
            reference.split('(')[1][:-1]
            for feature in ('attribute', 'object')
            for reference in re.findall(
                _event_report_regex % feature, event_report['content']
            )
        }
        for reference in references:
            if reference in self._event_report_matching:
                yield from self._event_report_matching[reference]

    ############################################################################
    #                       ATTRIBUTES PARSING FUNCTIONS                       #
    ############################################################################

    def _resolve_attribute(self, attribute: Union[MISPAttribute, dict]):
        attribute_type = attribute['type']
        try:
            to_call = self._mapping.attribute_types_mapping(attribute_type)
            if to_call is not None:
                getattr(self, to_call)(attribute)
            else:
                self._parse_custom_attribute(attribute)
                self._attribute_not_mapped_warning(attribute_type)
        except InvalidHashValueError:
            self._invalid_attribute_hash_value_error(attribute)
            self._parse_custom_attribute(attribute)
        except Exception as exception:
            self._attribute_error(attribute, exception)

    def _handle_attribute_indicator(
            self, attribute: Union[MISPAttribute, dict], pattern: str,
            indicator_args: Optional[dict] = None):
        indicator_id = self._parse_stix_object_id(
            'attribute', 'indicator', attribute
        )
        indicator_arguments = {
            'id': indicator_id, 'type': 'indicator',
            'labels': self._create_labels(attribute),
            'kill_chain_phases': self._create_killchain(attribute['category']),
            'created_by_ref': self.identity_id, 'interoperability': True
        }
        if indicator_args is not None:
            indicator_arguments.update(indicator_args)
        indicator_arguments['pattern'] = pattern
        indicator_arguments.update(
            self._handle_indicator_time_fields(attribute)
        )
        if attribute.get('comment'):
            indicator_arguments['description'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(
            attribute, indicator_id, indicator_arguments['modified']
        )
        if markings:
            self._handle_markings(indicator_arguments, markings)
        indicator = self._create_indicator(indicator_arguments)
        getattr(self, self._results_handling_function)(indicator)
        self._handle_analyst_data(indicator, attribute)
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], indicator_id)

    def _handle_attribute_observable(
            self, attribute: Union[MISPAttribute, dict],
            observable: Union[dict, list]):
        observable_id = self._parse_stix_object_id(
            'attribute', 'observed-data', attribute
        )
        observable_args = {
            'id': observable_id, 'type': 'observed-data',
            'labels': self._create_labels(attribute), 'number_observed': 1,
            'created_by_ref': self.identity_id, 'allow_custom': True,
            'interoperability': True
        }
        observable_args.update(self._handle_observable_time_fields(attribute))
        markings = self._handle_attribute_tags_and_galaxies(
            attribute, observable_id, observable_args['modified']
        )
        if markings:
            self._handle_markings(observable_args, markings)
        observed_data = self._create_observed_data(observable_args, observable)
        self._handle_analyst_data(observed_data, attribute)
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], observable_id)

    def _handle_attribute_tags_and_galaxies(
            self, attribute: Union[MISPAttribute, dict],
            object_id: str, timestamp: datetime) -> tuple:
        if attribute.get('Galaxy'):
            tag_names: list = []
            for galaxy in attribute['Galaxy']:
                galaxy_type = galaxy['type']
                to_call = self._mapping.galaxy_types_mapping(galaxy_type)
                if to_call is not None:
                    getattr(self, to_call.format('attribute'))(
                        galaxy, object_id, timestamp
                    )
                else:
                    self._handle_undefined_attribute_galaxy(
                        galaxy, object_id, timestamp
                    )
                tag_names.extend(self._quick_fetch_tag_names(galaxy))
            return tuple(
                tag['name'] for tag in attribute.get('Tag', [])
                if tag['name'] not in tag_names
            )
        return tuple(tag['name'] for tag in attribute.get('Tag', []))

    @staticmethod
    def _parse_AS_value(value: str) -> int:
        value = ''.join(
            digit for digit in value if digit.isnumeric() or digit == '.'
        )
        return int(value)

    def _parse_attachment_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('data'):
            if attribute.get('to_ids', False):
                value = self._handle_value_for_pattern(attribute['value'])
                file_pattern = self._create_filename_pattern(value)
                data = attribute['data']
                if not isinstance(data, str):
                    data = b64encode(data.getvalue()).decode()
                data_pattern = self._create_content_ref_pattern(
                    self._handle_value_for_pattern(data)
                )
                pattern = f"[{file_pattern} AND {data_pattern}]"
                self._handle_attribute_indicator(attribute, pattern)
            else:
                self._parse_attachment_attribute_observable(attribute)
        else:
            self._parse_filename_attribute(attribute)

    def _parse_autonomous_system_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            pattern = f"[{self._create_AS_pattern(value)}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_autonomous_system_attribute_observable(attribute)

    def _parse_campaign_name_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        campaign_id = self._parse_stix_object_id(
            'attribute', 'campaign', attribute
        )
        timestamp = self._parse_timestamp_value(attribute)
        campaign_args = {
            'id': campaign_id, 'type': 'campaign', 'name': attribute['value'],
            'created_by_ref': self.identity_id, 'created': timestamp,
            'modified': timestamp, 'labels': self._create_labels(attribute),
            'interoperability': True,
        }
        markings = self._handle_attribute_tags_and_galaxies(
            attribute, campaign_id, timestamp
        )
        if markings:
            self._handle_markings(campaign_args, markings)
        campaign = self._create_campaign(campaign_args)
        getattr(self, self._results_handling_function)(campaign)
        self._handle_analyst_data(campaign, attribute)
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], campaign_id)

    def _parse_custom_attribute(self, attribute: Union[MISPAttribute, dict]):
        custom_id = self._parse_stix_object_id(
            'attribute', 'x-misp-attribute', attribute
        )
        timestamp = self._parse_timestamp_value(attribute)
        custom_args = {
            'id': custom_id, 'created': timestamp, 'modified': timestamp,
            'labels': self._create_labels(attribute),
            'created_by_ref': self.identity_id,
            'x_misp_value': attribute['value'],
            'x_misp_type': attribute['type'],
            'x_misp_category': attribute['category'],
            'interoperability': True
        }
        if attribute.get('comment'):
            custom_args['x_misp_comment'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(
            attribute, custom_id, timestamp
        )
        if markings:
            self._handle_markings(custom_args, markings)
        custom_attribute = self._create_custom_attribute(custom_args)
        getattr(self, self._results_handling_function)(custom_attribute)
        self._handle_analyst_data(custom_attribute, attribute)
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], custom_id)

    def _parse_domain_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            pattern = f"[{self._create_domain_pattern(value)}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_domain_attribute_observable(attribute)

    def _parse_domain_ip_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            for separator in self.composite_separators:
                if separator in value:
                    domain, ip = value.split(separator)
                    domain_pattern = self._create_domain_pattern(domain)
                    resolving_ref = self._create_domain_resolving_pattern(ip)
                    pattern = f"[{domain_pattern} AND {resolving_ref}]"
                    self._handle_attribute_indicator(attribute, pattern)
                    break
            else:
                self._composite_attribute_value_warning(
                    attribute['type'], attribute['value']
                )
                self._parse_custom_attribute(attribute)
        else:
            self._parse_domain_ip_attribute_observable(attribute)

    def _parse_email_attachment_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                f"[email-message:body_multipart[*].body_raw_ref.name = '{value}']"
            )
        else:
            self._parse_email_attachment_attribute_observable(attribute)

    def _parse_email_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-addr:value = '{value}']"
            )
        else:
            self._parse_email_attribute_observable(attribute)

    def _parse_email_body_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-message:body = '{value}']"
            )
        else:
            self._parse_email_body_attribute_observable(attribute)

    def _parse_email_destination_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-message:to_refs[*].value = '{value}']"
            )
        else:
            self._parse_email_destination_attribute_observable(attribute)

    def _parse_email_header_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-message:received_lines = '{value}']"
            )
        else:
            self._parse_email_header_attribute_observable(attribute)

    def _parse_email_reply_to_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                f"[email-message:additional_header_fields.reply_to = '{value}']"
            )
        else:
            self._parse_email_reply_to_attribute_observable(attribute)

    def _parse_email_source_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-message:from_ref.value = '{value}']"
            )
        else:
            self._parse_email_source_attribute_observable(attribute)

    def _parse_email_subject_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[email-message:subject = '{value}']"
            )
        else:
            self._parse_email_subject_attribute_observable(attribute)

    def _parse_email_x_mailer_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                f"[email-message:additional_header_fields.x_mailer = '{value}']"
            )
        else:
            self._parse_email_x_mailer_attribute_observable(attribute)

    def _parse_filename_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[{self._create_filename_pattern(value)}]"
            )
        else:
            self._parse_filename_attribute_observable(attribute)

    def _parse_github_username_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            prefix = 'user-account'
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                f"[{prefix}:account_type = 'github' AND "
                f"{prefix}:account_login = '{value}']"
            )
        else:
            self._parse_github_username_attribute_observable(attribute)

    def _parse_hash_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            hash_value = self._create_hash_pattern(
                attribute['type'], attribute['value']
            )
            self._handle_attribute_indicator(attribute, f"[{hash_value}]")
        else:
            self._parse_hash_attribute_observable(attribute)

    def _parse_hash_composite_attribute(
            self, attribute: Union[MISPAttribute, dict],
            hash_type: Optional[str] = None):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            for separator in self.composite_separators:
                if separator in value:
                    if hash_type is None:
                        hash_type = attribute['type'].split('|')[1]
                    pattern = self._create_filename_hash_pattern(
                        hash_type, value, separator
                    )
                    self._handle_attribute_indicator(attribute, f"[{pattern}]")
                    break
            else:
                self._composite_attribute_value_warning(
                    attribute['type'], attribute['value']
                )
                self._handle_attribute_indicator(
                    attribute, f"[{self._create_filename_pattern(value)}]"
                )
        else:
            self._parse_hash_composite_attribute_observable(
                attribute, hash_type=hash_type
            )

    def _parse_hostname_port_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            for separator in self.composite_separators:
                if separator in value:
                    hostname, port = value.split(separator)
                    hostname_pattern = self._create_domain_pattern(hostname)
                    port_pattern = self._create_port_pattern(port)
                    self._handle_attribute_indicator(
                        attribute, f"[{hostname_pattern} AND {port_pattern}]"
                    )
                    break
            else:
                self._composite_attribute_value_warning(
                    attribute['type'], attribute['value']
                )
                self._parse_custom_attribute(attribute)
        else:
            self._parse_hostname_port_attribute_observable(attribute)

    def _parse_http_method_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                f"[network-traffic:extensions.'http-request-ext'.request_method = '{value}']"
            )
        else:
            self._parse_custom_attribute(attribute)

    def _parse_ip_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            ip_type = attribute['type'].split('-')[1]
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[{self._create_ip_pattern(ip_type, value)}]"
            )
        else:
            self._parse_ip_attribute_observable(attribute)

    def _parse_ip_port_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            for separator in self.composite_separators:
                if separator in value:
                    ip_type = attribute['type'].split('|')[0].split('-')[1]
                    ip_value, port_value = value.split(separator)
                    ip_pattern = self._create_ip_pattern(ip_type, ip_value)
                    port_pattern = self._create_port_pattern(
                        port_value, ip_type=ip_type
                    )
                    self._handle_attribute_indicator(
                        attribute, f"[{ip_pattern} AND {port_pattern}]"
                    )
                    break
            else:
                self._composite_attribute_value_warning(
                    attribute['type'], attribute['value']
                )
                self._parse_custom_attribute(attribute)
        else:
            self._parse_ip_port_attribute_observable(attribute)

    def _parse_mac_address_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[mac-addr:value = '{value}']"
            )
        else:
            self._parse_mac_address_attribute_observable(attribute)

    def _parse_malware_sample_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('data'):
            if attribute.get('to_ids', False):
                value = self._handle_value_for_pattern(attribute['value'])
                data = attribute['data']
                if not isinstance(data, str):
                    data = b64encode(data.getvalue()).decode()
                pattern = [
                    self._create_content_ref_pattern(
                        self._handle_value_for_pattern(data)
                    )
                ]
                for separator in self.composite_separators:
                    if separator in value:
                        pattern.append(
                            self._create_filename_hash_pattern(
                                'md5', value, separator
                            )
                        )
                        break
                else:
                    self._composite_attribute_value_warning(
                        attribute['type'], attribute['value']
                    )
                pattern.append(
                    self._mapping.malware_sample_additional_pattern_values()
                )
                self._handle_attribute_indicator(
                    attribute, f"[{' AND '.join(pattern)}]"
                )
            else:
                self._parse_malware_sample_attribute_observable(attribute)
        else:
            self._parse_hash_composite_attribute(attribute, hash_type='md5')

    def _parse_mutex_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[mutex:name = '{value}']"
            )
        else:
            self._parse_mutex_attribute_observable(attribute)

    def _parse_port_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[network-traffic:dst_port = '{value}']"
            )
        else:
            self._parse_custom_attribute(attribute)

    def _parse_regkey_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[{self._create_regkey_pattern(value)}]"
            )
        else:
            self._parse_regkey_attribute_observable(attribute)

    def _parse_regkey_value_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            for separator in self.composite_separators:
                if separator in value:
                    key, data = value.split(separator)
                    key_pattern = self._create_regkey_pattern(key)
                    self._handle_attribute_indicator(
                        attribute,
                        f'[{key_pattern} AND windows-registry-key:values.data'
                        f" = '{data.strip()}']"
                    )
                    break
            else:
                self._composite_attribute_value_warning(
                    attribute['type'], attribute['value']
                )
                self._handle_attribute_indicator(
                    attribute, f"[{self._create_regkey_pattern(value)}]"
                )
        else:
            self._parse_regkey_value_attribute_observable(attribute)

    def _parse_size_in_bytes_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[file:size = '{value}']"
            )
        else:
            self._parse_custom_attribute(attribute)

    def _parse_url_attribute(self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute, f"[url:value = '{value}']"
            )
        else:
            self._parse_url_attribute_observable(attribute)

    def _parse_user_agent_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            self._handle_attribute_indicator(
                attribute,
                "[network-traffic:extensions.'http-request-ext'."
                f"request_header.'User-Agent' = '{value}']"
            )
        else:
            self._parse_custom_attribute(attribute)

    def _parse_vulnerability_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        vulnerability_id = self._parse_stix_object_id(
            'attribute', 'vulnerability', attribute
        )
        timestamp = self._parse_timestamp_value(attribute)
        vulnerability_args = {
            'id': vulnerability_id, 'type': 'vulnerability',
            'name': attribute['value'], 'created': timestamp,
            'modified': timestamp, 'created_by_ref': self.identity_id,
            'labels': self._create_labels(attribute), 'interoperability': True,
            'external_references': [
                self._get_vulnerability_references(attribute['value'])
            ]
        }
        markings = self._handle_attribute_tags_and_galaxies(
            attribute, vulnerability_id, timestamp
        )
        if markings:
            self._handle_markings(vulnerability_args, markings)
        vulnerability = self._create_vulnerability(vulnerability_args)
        getattr(self, self._results_handling_function)(vulnerability)
        self._handle_analyst_data(vulnerability, attribute)
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], vulnerability_id)

    def _parse_x509_fingerprint_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            hash_type = attribute['type'].split('-')[-1].upper()
            value = ''.join(
                character for character in attribute['value']
                if character.isalnum()
            )
            if not self._check_hash_value(hash_type, value):
                raise InvalidHashValueError()
            self._handle_attribute_indicator(
                attribute, f"[x509-certificate:hashes.{hash_type} = '{value}']"
            )
        else:
            self._parse_x509_fingerprint_attribute_observable(attribute)

    ############################################################################
    #                      MISP OBJECTS PARSING FUNCTIONS                      #
    ############################################################################

    def _resolve_objects(self):
        for misp_object in self._misp_event['Object']:
            try:
                object_name = misp_object['name']
                to_call = self._mapping.objects_mapping(object_name)
                if to_call is not None:
                    getattr(self, to_call)(misp_object)
                else:
                    self._parse_custom_object(misp_object)
                    self._object_not_mapped_warning(object_name)
            except Exception as exception:
                self._object_error(misp_object, exception)

    def _extract_multiple_object_attributes_escaped(
            self, attributes: list,
            force_single: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if force_single is not None:
            for attribute in attributes:
                value = self._handle_value_for_pattern(attribute['value'])
                relation = attribute['object_relation']
                if relation in force_single:
                    attributes_dict[relation] = value
                else:
                    attributes_dict[relation].append(value)
            return attributes_dict
        for attribute in attributes:
            value = self._handle_value_for_pattern(attribute['value'])
            attributes_dict[attribute['object_relation']].append(value)
        return attributes_dict

    def _extract_multiple_object_attributes_with_data_escaped(
            self, attributes: list, force_single: tuple = (),
            with_data: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            value = self._handle_value_for_pattern(attribute['value'])
            if relation in with_data and attribute.get('data'):
                data = self._handle_value_for_pattern(attribute['data'])
                value = (value, data)
            if relation in force_single:
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    def _extract_object_attributes_escaped(self, attributes: list) -> dict:
        return {
            attribute['object_relation']: self._handle_value_for_pattern(attribute['value'])
            for attribute in attributes
        }

    def _handle_non_indicator_object(
            self, misp_object: Union[MISPObject, dict], object_args: dict,
            object_type: str, killchain: bool = False):
        object_id = self._parse_stix_object_id(
            'object', object_type, misp_object
        )
        timestamp = self._parse_timestamp_value(misp_object)
        object_args.update(
            {
                'id': object_id, 'type': object_type,
                'created_by_ref': self.identity_id, 'created': timestamp,
                'modified': timestamp, 'interoperability': True,
                'labels': self._create_object_labels(
                    misp_object,
                    to_ids=self._fetch_ids_flag(misp_object['Attribute'])
                )
            }
        )
        if killchain:
            object_args['kill_chain_phases'] = self._create_killchain(
                misp_object['meta-category']
            )
        markings = self._handle_object_tags_and_galaxies(
            misp_object, object_id, object_args['modified']
        )
        if markings:
            self._handle_markings(object_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], object_id,
                object_args['modified']
            )
        feature = f"_create_{object_type.replace('-', '_')}"
        stix_object = getattr(self, feature)(object_args)
        getattr(self, self._results_handling_function)(stix_object)
        self._handle_object_analyst_data(stix_object, misp_object)

    def _handle_object_indicator(
            self, misp_object: Union[MISPObject, dict], pattern: list):
        indicator_id = self._parse_stix_object_id(
            'object', 'indicator', misp_object
        )
        indicator_args = {
            'id': indicator_id, 'type': 'indicator',
            'labels': self._create_object_labels(misp_object, to_ids=True),
            'created_by_ref': self.identity_id, 'allow_custom': True,
            'pattern': f'[{" AND ".join(pattern)}]', 'interoperability': True,
            'kill_chain_phases': self._create_killchain(
                misp_object['meta-category']
            )
        }
        indicator_args.update(self._handle_indicator_time_fields(misp_object))
        if misp_object.get('comment'):
            indicator_args['description'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object, indicator_id, indicator_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], indicator_id,
                indicator_args['modified']
            )
        indicator = self._create_indicator(indicator_args)
        getattr(self, self._results_handling_function)(indicator)
        self._handle_object_analyst_data(indicator, misp_object)

    def _handle_object_observable(
            self, misp_object: Union[MISPObject, dict],
            observable: Union[dict, list]):
        observable_id = self._parse_stix_object_id(
            'object', 'observed-data', misp_object
        )
        observable_args = {
            'id': observable_id, 'type': 'observed-data',
            'labels': self._create_object_labels(misp_object, to_ids=False),
            'number_observed': 1, 'created_by_ref': self.identity_id,
            'allow_custom': True, 'interoperability': True
        }
        observable_args.update(self._handle_observable_time_fields(misp_object))
        markings = self._handle_object_tags_and_galaxies(
            misp_object, observable_id, observable_args['modified']
        )
        if markings:
            self._handle_markings(observable_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], observable_id,
                observable_args['modified']
            )
        observed_data = self._create_observed_data(observable_args, observable)
        self._handle_object_analyst_data(observed_data, misp_object)

    def _handle_object_tags_and_galaxies(
            self, misp_object: Union[MISPObject, dict],
            object_id: str, timestamp: datetime) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(
            misp_object
        )
        if galaxies:
            tag_names = set()
            for galaxy_type, galaxy in galaxies.items():
                to_call = self._mapping.galaxy_types_mapping(galaxy_type)
                if to_call is not None:
                    getattr(self, to_call.format('attribute'))(
                        galaxy, object_id, timestamp
                    )
                else:
                    self._handle_undefined_attribute_galaxy(
                        galaxy, object_id, timestamp
                    )
                tag_names.update(self._quick_fetch_tag_names(galaxy))
            return tuple(tag for tag in tags if tag not in tag_names)
        return tuple(tags)

    @staticmethod
    def _handle_observable_multiple_properties(attributes: dict) -> dict:
        properties = {'allow_custom': True}
        for key, values in attributes.items():
            feature = f"x_misp_{key.replace('-', '_')}"
            properties[feature] = (
                values[0] if isinstance(values, list) and len(values) == 1
                else values
            )
        return properties

    def _handle_observable_multiple_properties_with_data(
            self, attributes: dict, name: str) -> dict:
        properties = {'allow_custom': True}
        for key, values in attributes.items():
            feature = f"x_misp_{key.replace('-', '_')}"
            if key in getattr(self._mapping, f"{name}_data_fields")():
                properties[feature] = self._handle_custom_data_field(values)
                continue
            properties[feature] = (
                values[0] if isinstance(values, list) and len(values) == 1
                else values
            )
        return properties

    @staticmethod
    def _handle_observable_properties(attributes: dict) -> dict:
        properties = {'allow_custom': True}
        for key, value in attributes.items():
            properties[f"x_misp_{key.replace('-', '_')}"] = value
        return properties

    def _handle_parent_process_properties(self, attributes: dict) -> dict:
        parent_attributes = {
            '_'.join(key.split('-')[1:]): values
            for key, values in attributes.items()
        }
        return self._handle_observable_multiple_properties(parent_attributes)

    def _handle_pattern_multiple_properties(
            self, attributes: dict, prefix: str,
            separator: Optional[str] = ':') -> list:
        pattern = []
        for key, values in attributes.items():
            key = key.replace('-', '_')
            if not isinstance(values, list):
                pattern.append(f"{prefix}{separator}x_misp_{key} = '{values}'")
                continue
            for value in values:
                pattern.append(f"{prefix}{separator}x_misp_{key} = '{value}'")
        return pattern

    def _handle_pattern_properties(
            self, attributes: dict, prefix: str,
            separator: Optional[str] = ':') -> list:
        pattern = []
        for key, value in attributes.items():
            pattern.append(
                f"{prefix}{separator}x_misp_{key.replace('-', '_')} = '{value}'"
            )
        return pattern

    def _handle_pe_object_references(
            self, pe_object: dict, to_ids: list) -> Tuple[bool, list]:
        section_uuids = self._fetch_included_reference_uuids(
            pe_object['ObjectReference'],
            'pe-section'
        ) if pe_object.get('ObjectReference') else []
        if section_uuids:
            for section_uuid in section_uuids:
                section_ids, _ = self._objects_to_parse['pe-section'][
                    section_uuid
                ]
                to_ids.append(section_ids)
        return any(to_ids), section_uuids

    def _parse_account_object(self, misp_object: Union[MISPObject, dict]):
        name = misp_object['name'].replace('-', '_')
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=getattr(self._mapping, f"{name}_single_fields")()
            )
            pattern = [f"{prefix}:account_type = '{name.split('_')[0]}'"]
            mapping = getattr(self._mapping, f"{name}_object_mapping")()
            for key, feature in mapping.items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{feature} = '{attributes.pop(key)}'"
                    )
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_account_object_observable(misp_object, name)

    def _parse_account_object_with_attachment(
            self, misp_object: Union[MISPObject, dict]):
        name = misp_object['name'].replace('-', '_')
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes_with_data(
                misp_object['Attribute'],
                force_single=getattr(self._mapping, f"{name}_single_fields")(),
                with_data=getattr(self._mapping, f"{name}_data_fields")()
            )
            pattern = [f"{prefix}:account_type = '{name.split('_')[0]}'"]
            mapping = getattr(self._mapping, f"{name}_object_mapping")()
            for key, feature in mapping.items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{feature} = '{attributes.pop(key)}'"
                    )
            if attributes:
                for key, values in attributes.items():
                    for value in values:
                        pattern.extend(
                            self._handle_custom_data_pattern(
                                prefix, key.replace('-', '_'), value
                            )
                        )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_account_object_with_attachment_observable(
                misp_object, name
            )

    def _parse_android_app_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'software'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.android_app_single_fields()
            )
            mapping = self._mapping.android_app_object_mapping()
            pattern = [
                f"{prefix}:{feature} = '{attributes.pop(key)}'"
                for key, feature in mapping.items() if attributes.get(key)
            ]
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_android_app_object_observable(misp_object)

    def _parse_asn_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'autonomous-system'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.as_single_fields()
            )
            pattern = [self._create_AS_pattern(attributes.pop('asn'))]
            if attributes.get('description'):
                pattern.append(
                    f"{prefix}:name = '{attributes.pop('description')}'"
                )
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_asn_object_observable(misp_object)

    def _parse_attack_pattern_object(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_escaped(
            misp_object['Attribute'],
            force_single=self._mapping.attack_pattern_single_fields()
        )
        attack_pattern_args = defaultdict(list)
        for key, field in self._mapping.attack_pattern_object_mapping().items():
            if attributes.get(key):
                attack_pattern_args[field] = attributes.pop(key)
        for feature in ('id', 'references'):
            if attributes.get(feature):
                for value in attributes.pop(feature):
                    reference = self._parse_attack_pattern_reference(
                        feature, value
                    )
                    attack_pattern_args['external_references'].append(reference)
        if attributes:
            attack_pattern_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        self._handle_non_indicator_object(
            misp_object, attack_pattern_args, 'attack-pattern', killchain=True
        )

    def _parse_attack_pattern_reference(self, feature: str, value: str) -> dict:
        source_name, key = self._mapping.attack_pattern_reference_mapping(
            feature
        )
        if feature == 'id':
            if 'CAPEC' not in value:
                value = f"CAPEC-{value}"
        else:
            if 'mitre' not in value:
                source_name = 'external_url'
        return {'source_name': source_name, key: value}

    def _parse_course_of_action_object(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_escaped(
            misp_object['Attribute']
        )
        course_of_action_args = {}
        for feature in self._mapping.course_of_action_object_mapping():
            if attributes.get(feature):
                course_of_action_args[feature] = attributes.pop(feature)
        if attributes:
            course_of_action_args.update(
                self._handle_observable_properties(attributes)
            )
        self._handle_non_indicator_object(
            misp_object, course_of_action_args, 'course-of-action'
        )

    def _parse_cpe_asset_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'software'
            attributes = self._extract_object_attributes_escaped(
                misp_object['Attribute']
            )
            pattern = []
            for key, field in self._mapping.cpe_asset_object_mapping().items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{field} = '{attributes.pop(key)}'"
                    )
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_cpe_asset_object_observable(misp_object)

    def _parse_credential_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.credential_single_fields()
            )
            pattern = self._create_credential_pattern(attributes)
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(
                        attributes, 'user-account'
                    )
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_credential_object_observable(misp_object)

    @staticmethod
    def _parse_custom_attachment(attachment: Union[str, tuple]) -> dict:
        if isinstance(attachment, tuple):
            data = attachment[1]
            if not isinstance(data, str):
                data = b64encode(data.getvalue()).decode()
            attachment = {'value': attachment[0], 'data': data}
        return {'allow_custom': True, 'x_misp_attachment': attachment}

    def _parse_custom_object(self, misp_object: Union[MISPObject, dict]):
        custom_id = self._parse_stix_object_id(
            'object', 'x-misp-object', misp_object
        )
        timestamp = self._parse_timestamp_value(misp_object)
        custom_args = {
            'id': custom_id, 'created': timestamp, 'modified': timestamp,
            'labels': self._create_object_labels(misp_object),
            'created_by_ref': self.identity_id, 'interoperability': True,
            'x_misp_name': misp_object['name'],
            'x_misp_meta_category': misp_object['meta-category'],
            'x_misp_attributes': [
                self._parse_custom_object_attribute(attribute)
                for attribute in misp_object['Attribute']
            ]
        }
        if misp_object.get('comment'):
            custom_args['x_misp_comment'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object, custom_id, timestamp
        )
        if markings:
            self._handle_markings(custom_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], custom_id, timestamp
            )
        custom_object = self._create_custom_object(custom_args)
        getattr(self, self._results_handling_function)(custom_object)
        self._handle_object_analyst_data(custom_object, misp_object)

    @staticmethod
    def _parse_custom_object_attribute(
            attribute: Union[MISPAttribute, dict]) -> dict:
        custom_attribute = {
            key: attribute[key] for key in _object_attributes_fields
        }
        if '(s)' in custom_attribute['object_relation']:
            object_relation = custom_attribute.pop('object_relation')
            custom_attribute['object_relation'] = object_relation.replace(
                '(s)', ''
            )
        for field in _object_attributes_additional_fields:
            if attribute.get(field):
                custom_attribute[field] = attribute[field]
        if attribute.get('data'):
            data = attribute['data']
            if not isinstance(data, str):
                data = b64encode(data.getvalue()).decode()
            custom_attribute['data'] = data
        return custom_attribute

    def _parse_domain_ip_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'domain-name'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute']
            )
            special_case = ('domain' in attributes and 'hostname' in attributes)
            pattern = []
            for key, field in self._mapping.domain_ip_object_mapping().items():
                if attributes.get(key):
                    if key == 'hostname' and special_case:
                        field = 'x_misp_hostname'
                    for value in attributes.pop(key):
                        pattern.append(f"{prefix}:{field} = '{value}'")
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            case = self._fetch_domain_ip_object_case(misp_object['Attribute'])
            if case == 'exception':
                self._parse_custom_object(misp_object)
                self._required_fields_missing_warning('DomainName', 'domain-ip')
            else:
                getattr(self, f'_parse_domain_ip_object_{case}')(misp_object)

    def _parse_email_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'email-message'
            attributes = self._extract_multiple_object_attributes_with_data_escaped(
                misp_object['Attribute'],
                with_data=self._mapping.email_data_fields()
            )
            pattern = []
            for feature in ('to', 'cc', 'bcc'):
                if attributes.get(feature):
                    n = 0
                    display_names = self._parse_email_display_names(
                        attributes, feature
                    )
                    for value in attributes.pop(feature):
                        pattern.append(
                            f"{prefix}:{feature}_refs[{n}].value = '{value}'"
                        )
                        if value in display_names:
                            pattern.append(
                                f'{prefix}:{feature}_refs[{n}].display_name'
                                f" = '{display_names[value]}'"
                            )
                        n += 1
                    display_feature = f'{feature}-display-name'
                    if attributes.get(display_feature):
                        for display_name in attributes.pop(display_feature):
                            pattern.append(
                                f'{prefix}:{feature}_refs[{n}].display_name'
                                f" = '{display_name}'"
                            )
                            n += 1
            for key, feature in self._mapping.email_object_mapping().items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        pattern.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                n = 0
                for key in self._mapping.email_data_fields():
                    if not attributes.get(key):
                        continue
                    for name in attributes.pop(key):
                        feature = f'body_multipart[{n}]'
                        if isinstance(name, tuple):
                            name, data = name
                            pattern.append(
                                f'{prefix}:{feature}.body_raw_ref.payload_bin'
                                f" = '{data}'"
                            )
                        pattern.append(
                            f"{prefix}:{feature}.body_raw_ref.name = '{name}'"
                        )
                        pattern.append(
                            f"{prefix}:{feature}.content_disposition = '{key}'"
                        )
                        n += 1
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_email_object_observable(misp_object)

    def _parse_employee_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._parse_identity_args(misp_object, 'individual')
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.employee_single_fields()
        )
        if 'full-name' not in attributes:
            name = [
                attributes.pop(key) for key in ('first-name', 'last-name')
                if attributes.get(key)
            ]
            if name:
                identity_args['name'] = ' '.join(name)
        for key, feature in self._mapping.employee_object_mapping().items():
            if attributes.get(key):
                identity_args[feature] = attributes.pop(key)
        contact_information = self._parse_contact_information(
            attributes, misp_object['name']
        )
        if contact_information:
            identity_args['contact_information'] = ' / '.join(
                contact_information
            )
        if attributes:
            identity_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                    misp_object['ObjectReference'], identity_args['id'],
                    identity_args['modified']
                )
        identity = self._create_identity(identity_args)
        getattr(self, self._results_handling_function)(identity)
        self._handle_object_analyst_data(identity, misp_object)

    def _parse_file_object(self, misp_object: Union[MISPObject, dict]):
        to_ids = self._fetch_ids_flag(misp_object['Attribute'])
        if misp_object.get('ObjectReference'):
            for reference in misp_object['ObjectReference']:
                if self._is_reference_included(reference, 'pe'):
                    self._objects_to_parse['file'][misp_object['uuid']] = (
                        to_ids, misp_object
                    )
                    return
        if to_ids:
            pattern = self._parse_file_object_pattern(misp_object)
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_file_object_observable(misp_object)

    def _parse_file_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        file_args, observable_objects = self._parse_file_observable_object(
            misp_object
        )
        self._handle_file_observable_objects(file_args, observable_objects)
        self._handle_object_observable(misp_object, observable_objects)

    def _parse_file_object_pattern(
            self, misp_object: Union[MISPObject, dict]) -> list:
        prefix = 'file'
        attributes = self._extract_multiple_object_attributes_with_data_escaped(
            misp_object['Attribute'],
            force_single=self._mapping.file_single_fields(),
            with_data=self._mapping.file_data_fields()
        )
        pattern = []
        for hash_type in self._mapping.hash_attribute_types():
            if attributes.get(hash_type):
                try:
                    pattern.append(
                        self._create_hash_pattern(
                            hash_type, attributes[hash_type]
                        )
                    )
                    del attributes[hash_type]
                except InvalidHashValueError:
                    self._invalid_object_hash_value_error(
                        hash_type, misp_object
                    )
        for key, feature in self._mapping.file_object_mapping().items():
            if attributes.get(key):
                for value in attributes.pop(key):
                    pattern.append(f"{prefix}:{feature} = '{value}'")
        for key, feature in self._mapping.file_time_fields().items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('path'):
            value = attributes.pop('path')
            pattern.append(f"{prefix}:parent_directory_ref.path = '{value}'")
        if attributes.get('malware-sample'):
            malware_sample = attributes.pop('malware-sample')
            try:
                pattern.append(
                    self._parse_malware_sample_object_attribute(malware_sample)
                )
            except InvalidHashValueError:
                self._invalid_object_hash_value_error(
                    'malware-sample', misp_object
                )
                attributes['malware-sample'] = malware_sample[1]
        if attributes.get('attachment'):
            value = attributes.pop('attachment')
            if isinstance(value, tuple):
                value, data = value
                if not isinstance(data, str):
                    data = b64encode(data.getvalue()).decode()
                filename_pattern = self._create_content_ref_pattern(
                    value, 'x_misp_filename'
                )
                data_pattern = self._create_content_ref_pattern(data)
                pattern.append(f'({data_pattern} AND {filename_pattern})')
            else:
                pattern.append(
                    self._create_content_ref_pattern(value, 'x_misp_filename')
                )
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(attributes, prefix)
            )
        return pattern

    def _parse_http_request_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.http_request_single_fields()
            )
            patterns = []
            mapping = self._mapping.http_request_object_mapping('references')
            for key, feature in mapping.items():
                if attributes.get(key):
                    value = attributes.pop(key)
                    pattern = (
                        feature.format(self._define_address_type(value))
                        if 'ip-' in key else feature
                    )
                    patterns.append(f"({prefix}:{pattern} = '{value}')")
            extension = "extensions.'http-request-ext'"
            mapping = self._mapping.http_request_object_mapping(
                'request_extension'
            )
            for key, feature in mapping.items():
                if attributes.get(key):
                    patterns.append(
                        f'{prefix}:{extension}.{feature}'
                        f" = '{attributes.pop(key)}'"
                    )
            extension = f"{extension}.request_header"
            mapping = self._mapping.http_request_object_mapping(
                'request_header'
            )
            for key, feature in mapping.items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        patterns.append(
                            f"{prefix}:{extension}.'{feature}' = '{value}'"
                        )
            if attributes:
                patterns.extend(
                    self._handle_pattern_multiple_properties(
                        attributes, 'network-traffic'
                    )
                )
            self._handle_object_indicator(misp_object, patterns)
        else:
            self._parse_http_request_object_observable(misp_object)

    def _parse_image_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes_with_data_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.image_single_fields(),
                with_data=self._mapping.image_data_fields()
            )
            pattern = []
            if attributes.get('filename'):
                pattern.append(
                    self._create_filename_pattern(attributes.pop('filename'))
                )
            if attributes.get('attachment'):
                attachment = attributes.pop('attachment')
                if isinstance(attachment, tuple):
                    attachment, data = attachment
                    if not isinstance(data, str):
                        data = b64encode(data.getvalue()).decode()
                    pattern.append(self._create_content_ref_pattern(data))
                if '.' in attachment:
                    extension = attachment.split('.')[-1]
                    pattern.append(self._create_content_ref_pattern(
                        f'image/{extension}', 'mime_type')
                    )
                pattern.append(
                    self._create_content_ref_pattern(
                        attachment, 'x_misp_filename'
                    )
                )
            if attributes.get('url'):
                pattern.append(
                    self._create_content_ref_pattern(
                        attributes.pop('url'), 'url'
                    )
                )
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, 'file')
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_image_object_observable(misp_object)

    def _parse_intrusion_set_object(self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_data_escaped(
            misp_object['Attribute'],
            force_single=self._mapping.intrusion_set_single_fields()
        )
        intrusion_set_args = {}
        mapping = self._mapping.intrusion_set_object_mapping
        for key, feature in mapping('features').items():
            if attributes.get(key):
                intrusion_set_args[feature] = attributes.pop(key)
        for key, feature in mapping('timeline').items():
            if attributes.get(key):
                intrusion_set_args[feature] = self._datetime_from_str(
                    attributes.pop(key)
                )
        if attributes:
            intrusion_set_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        self._handle_non_indicator_object(
            misp_object, intrusion_set_args, 'intrusion-set'
        )

    def _parse_ip_port_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute']
            )
            patterns = []
            ip_mapping = self._mapping.ip_port_object_mapping('ip_features')
            for key, pattern in ip_mapping.items():
                if attributes.get(key):
                    for ip_value in attributes.pop(key):
                        identifier = pattern.format(
                            self._define_address_type(ip_value)
                        )
                        patterns.append(
                            f"({prefix}:{identifier} = '{ip_value}')"
                        )
            domain_mapping = self._mapping.ip_port_object_mapping(
                'domain_features'
            )
            for key, pattern in domain_mapping.items():
                if attributes.get(key):
                    for domain_value in attributes.pop(key):
                        patterns.append(
                            f"({prefix}:{pattern} = '{domain_value}')"
                        )
            for asset in ('features', 'timeline'):
                mapping = self._mapping.ip_port_object_mapping(asset)
                for key, feature in mapping.items():
                    if attributes.get(key):
                        for value in attributes.pop(key):
                            patterns.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                patterns.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, patterns)
        else:
            self._parse_ip_port_object_observable(misp_object)

    def _parse_legal_entity_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._parse_identity_args(misp_object, 'organization')
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.legal_entity_single_fields(),
            with_data=self._mapping.legal_entity_data_fields()
        )
        for key, feature in self._mapping.legal_entity_object_mapping().items():
            if attributes.get(key):
                identity_args[feature] = attributes.pop(key)
        name = misp_object['name'].replace('-', '_')
        contact_info = self._parse_contact_information(attributes, name)
        if contact_info:
            identity_args['contact_information'] = ' / '.join(contact_info)
        if attributes:
            identity_args.update(
                self._handle_observable_multiple_properties_with_data(
                    attributes, name
                )
            )
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                    misp_object['ObjectReference'], identity_args['id'],
                    identity_args['modified']
                )
        identity = self._create_identity(identity_args)
        getattr(self, self._results_handling_function)(identity)
        self._handle_object_analyst_data(identity, misp_object)

    def _parse_lnk_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'file'
            attributes = self._extract_multiple_object_attributes_with_data_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.lnk_single_fields(),
                with_data=self._mapping.lnk_data_fields()
            )
            pattern = []
            for key, feature in self._mapping.lnk_time_fields().items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{feature} = '{attributes.pop(key)}'"
                    )
            if attributes.get('filename'):
                for filename in attributes.pop('filename'):
                    pattern.append(f"{prefix}:name = '{filename}'")
            for feature in self._mapping.lnk_path_fields():
                if attributes.get(feature):
                    for value in attributes.pop(feature):
                        pattern.append(
                            f"{prefix}:parent_directory_ref.path = '{value}'"
                        )
            for hash_type in self._mapping.lnk_hash_types():
                if attributes.get(hash_type):
                    try:
                        pattern.append(
                            self._create_hash_pattern(
                                hash_type, attributes[hash_type]
                            )
                        )
                        del attributes[hash_type]
                    except InvalidHashValueError:
                        self._invalid_object_hash_value_error(
                            hash_type, misp_object
                        )
            if attributes.get('malware-sample'):
                malware_sample = attributes.pop('malware-sample')
                try:
                    pattern.append(
                        self._parse_malware_sample_object_attribute(
                            malware_sample
                        )
                    )
                except InvalidHashValueError:
                    self._invalid_object_hash_value_error(
                        'malware-sample', misp_object
                    )
                    attributes['malware-sample'] = malware_sample[1]
            for key, feature in self._mapping.lnk_object_mapping().items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{feature} = '{attributes.pop(key)}'"
                    )
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_lnk_object_observable(misp_object)

    def _parse_malware_sample_object_attribute(
            self, malware_sample: Union[str, tuple]) -> str:
        pattern = []
        if isinstance(malware_sample, tuple):
            malware_sample, data = malware_sample
            if not isinstance(data, str):
                data = b64encode(data.getvalue()).decode()
            pattern.append(self._create_content_ref_pattern(data))
        for separator in self.composite_separators:
            if separator in malware_sample:
                filename, md5 = malware_sample.split(separator)
                pattern.append(
                    self._create_content_ref_pattern(
                        filename, 'x_misp_filename'
                    )
                )
                if not self._check_hash_value('MD5', md5):
                    raise InvalidHashValueError()
                pattern.append(
                    self._create_content_ref_pattern(md5, 'hashes.MD5')
                )
                pattern.append(
                    self._mapping.malware_sample_additional_pattern_values()
                )
                break
        else:
            self._composite_attribute_value_warning(
                'malware-sample', malware_sample
            )
            pattern.append(
                self._create_content_ref_pattern(
                    malware_sample, 'x_misp_filename'
                )
            )
        return f"({' AND '.join(pattern)})"

    def _parse_mutex_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'mutex'
            attributes = self._extract_object_attributes_escaped(
                misp_object['Attribute']
            )
            pattern = []
            if attributes.get('name'):
                pattern.append(f"{prefix}:name = '{attributes.pop('name')}'")
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_mutex_object_observable(misp_object)

    def _parse_netflow_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_object_attributes_escaped(
                misp_object['Attribute']
            )
            pattern = []
            for ref_type in ('src', 'dst'):
                reference = []
                feature = f'{prefix}:{ref_type}_ref'
                if attributes.get(f'ip-{ref_type}'):
                    ip_value = attributes.pop(f'ip-{ref_type}')
                    ip_type = self._define_address_type(ip_value)
                    reference.extend(
                        (
                            f"{feature}.type = '{ip_type}'",
                            f"{feature}.value = '{ip_value}'"
                        )
                    )
                if attributes.get(f'{ref_type}-as'):
                    value = self._parse_AS_value(
                        attributes.pop(f'{ref_type}-as')
                    )
                    reference.append(
                        f"{feature}.belongs_to_refs[0].number = '{value}'"
                    )
                if reference:
                    pattern.append(f"({' AND '.join(reference)})")
            if attributes.get('protocol'):
                protocol = attributes.pop('protocol').lower()
                pattern.append(f"{prefix}:protocols[0] = '{protocol}'")
            for asset in ('features', 'timeline', 'extensions'):
                mapping = self._mapping.netflow_object_mapping(asset)
                for key, feature in mapping.items():
                    if attributes.get(key):
                        pattern.append(
                            f"{prefix}:{feature} = '{attributes.pop(key)}'"
                        )
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(
                        attributes, 'network-traffic'
                    )
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_netflow_object_observable(misp_object)

    def _parse_network_connection_object(
            self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_object_attributes_escaped(
                misp_object['Attribute']
            )
            pattern = self._parse_network_references_pattern(attributes)
            mapping = self._mapping.network_connection_mapping('features')
            for key, feature in mapping.items():
                if attributes.get(key):
                    pattern.append(
                        f"{prefix}:{feature} = '{attributes.pop(key)}'"
                    )
            index = 0
            for key in self._mapping.network_connection_mapping('protocols'):
                if attributes.get(key):
                    protocol = attributes.pop(key).lower()
                    pattern.append(
                        f"{prefix}:protocols[{index}] = '{protocol}'"
                    )
                    index += 1
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_network_connection_object_observable(misp_object)

    def _parse_network_references_pattern(self, attributes: dict) -> list:
        pattern = []
        for key in ('src', 'dst'):
            feature = f'network-traffic:{key}_ref'
            if attributes.get(f'ip-{key}'):
                value = attributes.pop(f'ip-{key}')
                ip_type = self._define_address_type(value)
                pattern.append(
                    f"({feature}.type = '{ip_type}' AND "
                    f"{feature}.value = '{value}')"
                )
            if attributes.get(f'hostname-{key}'):
                value = attributes.pop(f'hostname-{key}')
                pattern.append(
                    f"({feature}.type = 'domain-name' AND "
                    f"{feature}.value = '{value}')"
                )
        return pattern

    def _parse_network_socket_object_pattern(
            self, object_attributes: list) -> list:
        attributes = self._extract_multiple_object_attributes_escaped(
                object_attributes,
                force_single=self._mapping.network_socket_single_fields()
            )
        prefix = 'network-traffic'
        pattern = self._parse_network_references_pattern(attributes)
        socket_mapping = self._mapping.network_socket_mapping('features')
        for key, feature in socket_mapping.items():
            if attributes.get(key):
                pattern.append(
                    f"{prefix}:{feature} = '{attributes.pop(key)}'"
                )
        if attributes.get('protocol'):
            protocol = attributes.pop('protocol').lower()
            pattern.append(
                f"{prefix}:protocols[0] = '{protocol}'"
            )
        prefix = f"{prefix}:extensions.'socket-ext'"
        extension_mapping = self._mapping.network_socket_mapping('extension')
        for key, feature in extension_mapping.items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        if attributes.get('state'):
            for state in attributes.pop('state'):
                if state in self._mapping.network_socket_state_fields():
                    pattern.append(f"{prefix}.is_{state} = true")
                else:
                    attributes['state'].append(state)
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(
                    attributes, 'network-traffic'
                )
            )
        return pattern

    def _parse_news_agency_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._parse_identity_args(misp_object, 'organization')
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.news_agency_single_fields(),
            with_data=self._mapping.news_agency_data_fields()
        )
        for key, feature in self._mapping.news_agency_object_mapping().items():
            if attributes.get(key):
                identity_args[feature] = attributes.pop(key)
        name = misp_object['name'].replace('-', '_')
        contact_info = self._parse_contact_information(attributes, name)
        if contact_info:
            identity_args['contact_information'] = ' / '.join(contact_info)
        if attributes:
            identity_args.update(
                self._handle_observable_multiple_properties_with_data(
                    attributes, name
                )
            )
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                    misp_object['ObjectReference'], identity_args['id'],
                    identity_args['modified']
                )
        identity = self._create_identity(identity_args)
        getattr(self, self._results_handling_function)(identity)
        self._handle_object_analyst_data(identity, misp_object)

    def _parse_person_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._parse_identity_args(misp_object, 'individual')
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.person_single_fields()
        )
        if 'full-name' not in attributes:
            name_features = ('first-name', 'middle-name', 'last-name')
            name = [
                attributes.pop(key) for key in name_features
                if attributes.get(key)
            ]
            if name:
                identity_args['name'] = ' '.join(name)
        for key, feature in self._mapping.person_object_mapping().items():
            if attributes.get(key):
                identity_args[feature] = attributes.pop(key)
        contact_information = self._parse_contact_information(
            attributes,
            misp_object['name']
        )
        if contact_information:
            identity_args['contact_information'] = ' / '.join(
                contact_information
            )
        if attributes:
            identity_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], identity_args['id'],
                identity_args['modified']
            )
        identity = self._create_identity(identity_args)
        getattr(self, self._results_handling_function)(identity)
        self._handle_object_analyst_data(identity, misp_object)

    def _parse_organization_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._parse_identity_args(misp_object, 'organization')
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.organization_single_fields()
        )
        for key, feature in self._mapping.organization_object_mapping().items():
            if attributes.get(key):
                identity_args[feature] = attributes.pop(key)
        contact_info = self._parse_contact_information(
            attributes,
            misp_object['name'].replace('-', '_')
        )
        if contact_info:
            identity_args['contact_information'] = ' / '.join(contact_info)
        if attributes:
            identity_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], identity_args['id'],
                identity_args['modified']
            )
        identity = self._create_identity(identity_args)
        getattr(self, self._results_handling_function)(identity)
        self._handle_object_analyst_data(identity, misp_object)

    def _parse_pe_extensions_observable(
            self, pe_object: dict, uuids: Optional[list] = None) -> dict:
        custom = False
        attributes = self._extract_multiple_object_attributes_escaped(
            pe_object['Attribute'],
            force_single=self._mapping.pe_object_single_fields()
        )
        extension = defaultdict(list)
        for key, feature in self._mapping.pe_object_mapping('features').items():
            if attributes.get(key):
                extension[feature] = attributes.pop(key)
        optional_header = {}
        for key, feature in self._mapping.pe_object_mapping('header').items():
            if attributes.get(key):
                optional_header[feature] = attributes.pop(key)
        if optional_header:
            extension['optional_header'] = optional_header
        if attributes:
            custom = True
            extension.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if uuids is not None:
            for section_uuid in uuids:
                section = defaultdict(dict)
                pe_section = self._objects_to_parse['pe-section'].pop(
                    section_uuid
                )
                attributes = self._extract_object_attributes_escaped(
                    pe_section[1]['Attribute']
                )
                for key, feature in self._mapping.pe_section_mapping().items():
                    if attributes.get(key):
                        section[feature] = attributes.pop(key)
                for attribute_type in self._mapping.file_hash_main_types():
                    if attributes.get(attribute_type):
                        value = self._select_single_feature(
                            attributes, attribute_type
                        )
                        hash_type = self._define_hash_type(attribute_type)
                        if self._check_hash_value(hash_type, value):
                            section['hashes'][hash_type] = value
                        else:
                            self._invalid_object_hash_value_error(
                                attribute_type, pe_object
                            )
                            attributes[attribute_type].append(value)
                if attributes:
                    custom = True
                    section.update(
                        self._handle_observable_multiple_properties(attributes)
                    )
                extension['sections'].append(
                    self._create_windowsPESection(section)
                )
        return self._create_PE_extension(extension), custom

    def _parse_pe_extensions_pattern(
            self, pe_object: dict, uuids: Optional[list] = None) -> list:
        prefix = "file:extensions.'windows-pebinary-ext'"
        attributes = self._extract_multiple_object_attributes_escaped(
            pe_object['Attribute'],
            force_single=self._mapping.pe_object_single_fields()
        )
        pattern = []
        for key, feature in self._mapping.pe_object_mapping('features').items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        for key, feature in self._mapping.pe_object_mapping('header').items():
            if attributes.get(key):
                value = attributes.pop(key)
                pattern.append(
                    f"{prefix}.optional_header.{feature} = '{value}'"
                )
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(
                    attributes, prefix, separator='.'
                )
            )
        if uuids is not None:
            for section_uuid in uuids:
                section_prefix = f"{prefix}.sections[{uuids.index(section_uuid)}]"
                section_object = self._objects_to_parse['pe-section'].pop(section_uuid)[1]
                attributes = self._extract_object_attributes_escaped(
                    section_object['Attribute']
                )
                for key, feature in self._mapping.pe_section_mapping().items():
                    if attributes.get(key):
                        value = attributes.pop(key)
                        pattern.append(
                            f"{section_prefix}.{feature} = '{value}'"
                        )
                for hash_type in self._mapping.pe_section_hash_types():
                    if attributes.get(hash_type):
                        try:
                            pattern.append(
                                self._create_hash_pattern(
                                    hash_type, attributes[hash_type],
                                    prefix=f'{section_prefix}.hashes'
                                )
                            )
                            del attributes[hash_type]
                        except InvalidHashValueError:
                            self._invalid_object_hash_value_error(
                                hash_type, section_object
                            )
                if attributes:
                    pattern.extend(
                        self._handle_pattern_properties(
                            attributes, section_prefix, separator='.'
                        )
                    )
        return pattern

    def _parse_process_object_pattern(self, object_attributes: list) -> list:
        attributes = self._extract_multiple_object_attributes_escaped(
            object_attributes,
            force_single=self._mapping.process_single_fields()
        )
        prefix = 'process'
        pattern = []
        process_mapping = self._mapping.process_object_mapping('features')
        for key, feature in process_mapping.items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('image'):
            pattern.append(
                self._create_process_image_pattern(attributes.pop('image'))
            )
        parent_attributes = self._extract_parent_process_attributes(attributes)
        parent_mapping = self._mapping.process_object_mapping('parent')
        for key, feature in parent_mapping.items():
            if parent_attributes.get(key):
                value = parent_attributes.pop(key)
                pattern.append(f"{prefix}:parent_ref.{feature} = '{value}'")
        if parent_attributes:
            parent_attributes = {
                '_'.join(key.split('-')[1:]): values
                for key, values in parent_attributes.items()
            }
            pattern.extend(
                self._handle_pattern_multiple_properties(
                    parent_attributes, prefix, separator=':parent_ref.'
                )
            )
        if attributes.get('child-pid'):
            index = 0
            for child_pid in attributes.pop('child-pid'):
                pattern.append(
                    f"{prefix}:child_refs[{index}].pid = '{child_pid}'"
                )
                index += 1
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(attributes, prefix)
            )
        return pattern

    def _parse_registry_key_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'windows-registry-key'
            attributes = self._extract_object_attributes(
                misp_object['Attribute']
            )
            pattern = self._parse_regkey_key_values_pattern(
                attributes, prefix
            )
            values_prefix = f"{prefix}:values[0]"
            if attributes.get('data'):
                data = self._sanitize_registry_key_value(
                    attributes.pop('data').strip("'").strip('"')
                )
                pattern.append(f"{values_prefix}.data = '{data}'")
            attributes = {
                key: self._handle_value_for_pattern(value)
                for key, value in attributes.items()
            }
            for key, feature in self._mapping.registry_key_mapping().items():
                if attributes.get(key):
                    pattern.append(
                        f"{values_prefix}.{feature} = '{attributes.pop(key)}'"
                    )
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_registry_key_object_observable(misp_object)

    def _parse_script_object(self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.script_single_fields(),
            with_data=self._mapping.script_data_fields()
        )
        object_type = (
            'malware' if 'state' in attributes
            and 'Malicious' in attributes['state'] else 'tool'
        )
        object_args = {}
        mapping = getattr(self._mapping, f'script_to_{object_type}_mapping')
        for key, feature in mapping().items():
            if key in attributes:
                object_args[feature] = attributes.pop(key)
        if attributes:
            object_args.update(
                self._handle_observable_multiple_properties_with_data(
                    attributes, misp_object['name']
                )
            )
        self._handle_non_indicator_object(
            misp_object, object_args, object_type, killchain=True
        )

    def _parse_stix_pattern_object(self, misp_object: Union[MISPObject, dict]):
        indicator_args = {}
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            feature = self._mapping.stix_pattern_object_mapping(relation)
            if feature is not None:
                if relation == 'version':
                    indicator_args[feature] = attribute['value'].strip(
                        'stixSTIX '
                    )
                    continue
                indicator_args[feature] = attribute['value']
        self._handle_patterning_object_indicator(misp_object, indicator_args)

    def _parse_url_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'url'
            attributes = self._extract_object_attributes_escaped(
                misp_object['Attribute']
            )
            pattern = []
            if attributes.get('url'):
                pattern.append(f"{prefix}:value = '{attributes.pop('url')}'")
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_url_object_observable(misp_object)

    def _parse_user_account_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes_with_data_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.user_account_single_fields(),
                with_data=self._mapping.user_account_data_fields()
            )
            pattern = []
            for data_type in ('features', 'timeline'):
                mapping = self._mapping.user_account_object_mapping(data_type)
                for key, feature in mapping.items():
                    if attributes.get(key):
                        pattern.append(
                            f"{prefix}:{feature} = '{attributes.pop(key)}'"
                        )
            extension_prefix = f"{prefix}:extensions.'unix-account-ext'"
            mapping = self._mapping.user_account_object_mapping('extension')
            for key, feature in mapping.items():
                if attributes.get(key):
                    values = attributes.pop(key)
                    if isinstance(values, list):
                        for value in values:
                            pattern.append(
                                f"{extension_prefix}.{feature} = '{value}'"
                            )
                    else:
                        pattern.append(
                            f"{extension_prefix}.{feature} = '{values}'"
                        )
            if attributes:
                for key, values in attributes.items():
                    if isinstance(values, list):
                        for value in values:
                            pattern.extend(
                                self._handle_custom_data_pattern(
                                    prefix, key.replace('-', '_'), value
                                )
                            )
                    else:
                        pattern.extend(
                            self._handle_custom_data_pattern(
                                prefix, key.replace('-', '_'), values
                            )
                        )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_user_account_object_observable(misp_object)

    def _parse_vulnerability_object(self, misp_object: Union[MISPObject, dict]):
        vulnerability_args = defaultdict(list)
        attributes = self._extract_multiple_object_attributes_escaped(
            misp_object['Attribute']
        )
        if attributes.get('id'):
            vulnerability_args['name'] = attributes['id'][0]
            for vuln in attributes.pop('id'):
                reference = {
                    'external_id': vuln, 'source_name': (
                        'cve' if vuln.startswith('CVE') else 'vulnerability'
                    )
                }
                vulnerability_args['external_references'].append(reference)
        for feature in ('description', 'summary'):
            if attributes.get(feature):
                vulnerability_args['description'] = self._select_single_feature(
                    attributes, feature
                )
                break
        if attributes.get('references'):
            for reference in attributes.pop('references'):
                vulnerability_args['external_references'].append(
                    {'source_name': 'url', 'url': reference}
                )
        if attributes:
            vulnerability_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        self._handle_non_indicator_object(
            misp_object, vulnerability_args, 'vulnerability'
        )

    def _parse_x509_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'x509-certificate'
            attributes = self._extract_multiple_object_attributes_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.x509_single_fields()
            )
            pattern = []
            if attributes.get('self_signed'):
                value = attributes.pop('self_signed')
                pattern.append(
                    f"{prefix}:is_self_signed = '{value}'"
                )
            for attribute_type in self._mapping.x509_hash_fields():
                if attributes.get(attribute_type):
                    hash_type = self._define_hash_type(
                        attribute_type.split('-')[-1]
                    )
                    valid_hash = self._check_hash_value(
                        hash_type, attributes[attribute_type]
                    )
                    if valid_hash:
                        value = attributes.pop(attribute_type)
                        pattern.append(
                            f"{prefix}:hashes.{hash_type} = '{value}'"
                        )
                    else:
                        self._invalid_object_hash_value_error(
                            attribute_type, misp_object
                        )
            for data_type in ('features', 'timeline'):
                mapping = self._mapping.x509_object_mapping(data_type)
                for key, feature in mapping.items():
                    if attributes.get(key):
                        pattern.append(
                            f"{prefix}:{feature} = '{attributes.pop(key)}'"
                        )
            extension = []
            mapping = self._mapping.x509_object_mapping('extension')
            for key, feature in mapping.items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        extension.append(f"{feature}:{value}")
            if extension:
                name = ','.join(extension)
                pattern.append(
                    f'{prefix}:x509_v3_extensions.'
                    f"subject_alternative_name = '{name}'"
                )
            if attributes:
                pattern.extend(
                    self._handle_pattern_properties(attributes, prefix)
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_x509_object_observable(misp_object)

    def _populate_objects_to_parse(self, misp_object: Union[MISPObject, dict]):
        to_ids = self._fetch_ids_flag(misp_object['Attribute'])
        self._objects_to_parse[misp_object['name']][misp_object['uuid']] = (
            to_ids, misp_object
        )

    def _resolve_file_to_parse(
            self, file_object: dict, file_uuid: str, file_ids: bool):
        pe_uuid = self._fetch_included_reference_uuids(
            file_object['ObjectReference'], 'pe'
        )
        pe_found = len(pe_uuid)
        if pe_found != 1:
            if pe_found == 0:
                self._pe_reference_warning(file_uuid)
            else:
                self._unclear_pe_references_warning(file_uuid, pe_uuid)
            if file_ids:
                pattern = self._parse_file_object_pattern(file_object)
                self._handle_object_indicator(file_object, pattern)
            else:
                self._parse_file_object_observable(file_object)
            return
        pe_uuid = pe_uuid[0]
        pe_ids, pe_object = self._objects_to_parse['pe'].pop(pe_uuid)
        to_ids, section_uuids = self._handle_pe_object_references(
            pe_object, [file_ids, pe_ids]
        )
        if to_ids:
            pattern = self._parse_file_object_pattern(file_object)
            pattern.extend(
                self._parse_pe_extensions_pattern(pe_object, section_uuids)
            )
            self._handle_object_indicator(file_object, pattern)
        else:
            file_args, observable = self._parse_file_observable_object(
                file_object
            )
            try:
                extension_args, custom = self._parse_pe_extensions_observable(
                    pe_object, section_uuids
                )
                file_args['extensions'] = {
                    'windows-pebinary-ext': extension_args
                }
            except Exception as exception:
                self._object_error(pe_object, exception)
            if 'allow_custom' not in file_args and custom:
                file_args['allow_custom'] = custom
            self._handle_file_observable_objects(file_args, observable)
            self._handle_object_observable(file_object, observable)

    def _resolve_objects_to_parse(self):
        if self._objects_to_parse.get('file'):
            file_objects = self._objects_to_parse.pop('file')
            for file_uuid, misp_object in file_objects.items():
                to_ids, file_object = misp_object
                try:
                    self._resolve_file_to_parse(file_object, file_uuid, to_ids)
                except Exception as exception:
                    self._object_error(file_object, exception)
        if self._objects_to_parse.get('pe'):
            for misp_object in self._objects_to_parse.pop('pe').values():
                try:
                    to_ids, pe_object = misp_object
                except TypeError:
                    continue
                try:
                    self._resolve_pe_to_parse(pe_object, to_ids)
                except Exception as exception:
                    self._object_error(pe_object, exception)
        if self._objects_to_parse.get('pe-section'):
            pe_section = self._objects_to_parse.pop('pe-section')
            for misp_object in pe_section.values():
                self._parse_custom_object(misp_object[1])

    def _resolve_pe_to_parse(self, pe_object: dict, pe_ids: bool):
        to_ids, section_uuids = self._handle_pe_object_references(
            pe_object, [pe_ids]
        )
        if to_ids:
            pattern = self._parse_pe_extensions_pattern(
                pe_object, section_uuids
            )
            self._handle_object_indicator(pe_object, pattern)
        else:
            try:
                extension_args, custom = self._parse_pe_extensions_observable(
                    pe_object, section_uuids
                )
                file_args = {
                    'extensions': {'windows-pebinary-ext': extension_args}
                }
                for feature in ('original', 'internal'):
                    if extension_args.get(f'x_misp_{feature}_filename'):
                        file_args['name'] = extension_args[
                            f'x_misp_{feature}_filename'
                        ]
                        break
                else:
                    file_args['name'] = ''
                if custom:
                    file_args['allow_custom'] = custom
                observable = self._handle_file_observable_object(file_args)
                self._handle_object_observable(pe_object, observable)
            except Exception as exception:
                self._object_error(pe_object, exception)

    ############################################################################
    #                        GALAXIES PARSING FUNCTIONS                        #
    ############################################################################

    def _check_external_references(
            self, references: list, values: list, feature: str) -> bool:
        for reference in references:
            to_return = (
                reference['source_name'] in self._mapping.source_names()
                and reference[feature] in values
            )
            if to_return:
                return True
        return False

    def _check_galaxy_matching(
            self, cluster: dict, *args: Tuple[str, str]) -> Union[str, None]:
        if self._check_galaxy_name(*args):
            return self._fetch_galaxy_matching_by_name(*args)
        if cluster.get('meta') is not None:
            meta = cluster['meta']
            key = 'external_id'
            for key, feature in zip((key, 'refs'), (key, 'url')):
                if meta.get(key) is None:
                    continue
                if self._check_galaxy_references(meta[key], feature, *args):
                    return self._fetch_galaxy_matching_by_reference(
                        meta[key], feature, *args
                    )

    def _check_galaxy_name(self, name: str, object_type: str) -> bool:
        names = 0
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] == name:
                names += 1
        return names == 1

    def _check_galaxy_references(self, values: str, feature: str, name: str,
                                 object_type: str) -> bool:
        numbers = 0
        for stix_object in self._galaxies_catalog[name][object_type]:
            to_continue = (
                stix_object['name'] != name
                or not stix_object.get('external_references')
            )
            if to_continue:
                continue
            has_reference = self._check_external_references(
                stix_object['external_references'], values, feature
            )
            if has_reference:
                numbers += 1
        return numbers == 1

    def _define_source_name(self, value: str) -> str:
        id_mapping = self._mapping.external_id_to_source_name
        for prefix, source_name in id_mapping().items():
            if value.startswith(f'{prefix}-'):
                return source_name
        if '-' in value:
            return 'NIST Mobile Threat Catalogue'
        if value.isnumeric():
            return 'WASC'
        return 'mitre-attack'

    def _fetch_galaxy_matching_by_name(
            self, name: str, object_type: str) -> Union[str, None]:
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] == name:
                self._handle_galaxy_matching(object_type, stix_object)
                return stix_object['id']

    def _fetch_galaxy_matching_by_reference(
            self, values: list, feature: str, name: str,
            object_type: str) -> Union[str, None]:
        for stix_object in self._galaxies_catalog[name][object_type]:
            to_continue = (
                stix_object['name'] != name
                or not stix_object.get('external_references')
            )
            if to_continue:
                continue
            has_reference = self._check_external_references(
                stix_object['external_references'], values, feature
            )
            if has_reference:
                self._handle_galaxy_matching(object_type, stix_object)
                return stix_object['id']

    def _handle_attribute_galaxy_relationships(
            self, source_id: str, target_ids: list, timestamp: datetime):
        relationships = self._mapping.relationship_specs(
            source_id.split('--')[0]
        )
        if relationships is None:
            for target_id in target_ids:
                self._parse_galaxy_relationship(
                    source_id, target_id, 'related-to', timestamp
                )
        else:
            for target_id in target_ids:
                target_type = target_id.split('--')[0]
                self._parse_galaxy_relationship(
                    source_id, target_id,
                    relationships.get(target_type, 'related-to'), timestamp
                )
        self._handle_object_refs(target_ids)

    def _handle_external_references(self, values: list) -> list:
        references = []
        for value in values:
            external_id = {
                'source_name': self._define_source_name(value),
                'external_id': value
            }
            references.append(external_id)
        return references

    def _handle_galaxy_matching(self, object_type: str, stix_object: dict):
        identity_id = stix_object['created_by_ref']
        if identity_id not in self.unique_ids:
            identity = self._create_identity(self._identities[identity_id])
            self.__objects.insert(0, identity)
            self.__index += 1
            self.__ids[identity_id] = identity_id
        stix_object['allow_custom'] = True
        self._append_SDO_without_refs(
            getattr(self, f"_create_{object_type.replace('-', '_')}")(
                stix_object
            )
        )

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            if object_ref not in self.__object_refs:
                self.__object_refs.append(object_ref)

    def _handle_undefined_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_undefined_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _handle_undefined_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_undefined_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _handle_undefined_parent_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_undefined_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _is_galaxy_parsed(self, object_refs: list, cluster: dict) -> bool:
        object_id = cluster['uuid']
        if object_id in self.unique_ids:
            object_refs.append(self.unique_ids[object_id])
            return True
        if self.interoperability:
            object_type = self._mapping.cluster_to_stix_object(cluster['type'])
            value = cluster['value']
            try:
                in_catalog = value in self._galaxies_catalog
            except AttributeError:
                self._generate_galaxies_catalog()
                in_catalog = value in self._galaxies_catalog
            if in_catalog:
                if object_type in self._galaxies_catalog[value]:
                    args = (value, object_type)
                    stix_object_id = self._check_galaxy_matching(cluster, *args)
                    if stix_object_id is not None:
                        object_refs.append(stix_object_id)
                        self.__ids[object_id] = stix_object_id
                        return True
                return False
            if ' - ' in value:
                for part in value.split(' - '):
                    if object_type in self._galaxies_catalog.get(part, {}):
                        stix_object_id = self._check_galaxy_matching(
                            cluster, part, object_type
                        )
                        if stix_object_id is not None:
                            object_refs.append(stix_object_id)
                            self.__ids[object_id] = stix_object_id
                            return True
        return False

    def _parse_attack_pattern_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_attack_pattern_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_attack_pattern_event_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_attack_pattern_galaxy(
            galaxy, self.event_timestamp
        )
        self._handle_object_refs(object_refs)

    def _parse_attack_pattern_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            attack_pattern_id = f"attack-pattern--{cluster['uuid']}"
            attack_pattern_args = self._create_galaxy_args(
                cluster, galaxy['name'], attack_pattern_id, timestamp
            )
            self._append_SDO_without_refs(
                self._create_attack_pattern(attack_pattern_args)
            )
            object_refs.append(attack_pattern_id)
            self.__ids[cluster['uuid']] = attack_pattern_id
        return object_refs

    def _parse_attack_pattern_parent_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_attack_pattern_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_campaign_attribute_galaxy(
            self, galaxy: MISPGalaxy | dict,
            object_id: str, timestamp: datetime):
        object_refs = self._parse_campaign_galaxy(galaxy)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_campaign_event_galaxy(self, galaxy: MISPGalaxy | dict):
        object_refs = self._parse_campaign_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _parse_campaign_galaxy(
            self, galaxy: MISPGalaxy | dict,
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            campaign_id = f"campaign--{cluster['uuid']}"
            campaign_args = self._create_galaxy_args(
                cluster, galaxy['name'], campaign_id, timestamp
            )
            campaign = self._create_campaign(campaign_args)
            self._append_SDO_without_refs(campaign)
            object_refs.append(campaign_id)
            self.__ids[cluster['uuid']] = campaign_id
        return object_refs

    def _parse_campaign_parent_galaxy(self, galaxy: MISPGalaxy | dict):
        object_refs = self._parse_campaign_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_course_of_action_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_course_of_action_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_course_of_action_event_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_course_of_action_galaxy(
            galaxy, self.event_timestamp
        )
        self._handle_object_refs(object_refs)

    def _parse_course_of_action_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            course_of_action_id = f"course-of-action--{cluster['uuid']}"
            course_of_action_args = self._create_galaxy_args(
                cluster, galaxy['name'], course_of_action_id, timestamp
            )
            course_of_action = self._create_course_of_action(
                course_of_action_args
            )
            self._append_SDO_without_refs(course_of_action)
            object_refs.append(course_of_action_id)
            self.__ids[cluster['uuid']] = course_of_action_id
        return object_refs

    def _parse_course_of_action_parent_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_course_of_action_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_external_id(self, external_id: str) -> dict:
        return {
            'source_name': self._define_source_name(external_id),
            'external_id': external_id
        }

    def _parse_external_references(
            self, meta_args: dict, values: Union[list, str],
            feature: Optional[str] = '_parse_external_id'):
        if isinstance(values, list):
            meta_args['external_references'].extend(
                getattr(self, feature)(value) for value in values
            )
        else:
            meta_args['external_references'].append(
                getattr(self, feature)(values)
            )

    @staticmethod
    def _parse_external_url(url: str) -> dict:
        return {'source_name': 'url', 'url': url}

    def _parse_intrusion_set_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_intrusion_set_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_intrusion_set_event_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_intrusion_set_galaxy(
            galaxy, self.event_timestamp
        )
        self._handle_object_refs(object_refs)

    def _parse_intrusion_set_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            intrusion_set_id = f"intrusion-set--{cluster['uuid']}"
            intrusion_set_args = self._create_galaxy_args(
                cluster, galaxy['name'], intrusion_set_id, timestamp
            )
            intrusion_set = self._create_intrusion_set(intrusion_set_args)
            self._append_SDO_without_refs(intrusion_set)
            object_refs.append(intrusion_set_id)
            self.__ids[cluster['uuid']] = intrusion_set_id
        return object_refs

    def _parse_intrusion_set_parent_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_intrusion_set_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    @staticmethod
    def _parse_kill_chain(meta_args: dict, values: list):
        if not isinstance(values, list):
            values = [values]
        for value in values:
            name, *_, phase = value.split(':')
            meta_args['kill_chain_phases'].append(
                {'kill_chain_name': name, 'phase_name': phase}
            )

    def _parse_malware_attribute_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                                        object_id: str, timestamp: datetime):
        object_refs = self._parse_malware_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_malware_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_malware_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _parse_malware_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                              timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            malware_id = f"malware--{cluster['uuid']}"
            malware_args = self._create_galaxy_args(
                cluster, galaxy['name'], malware_id, timestamp
            )
            malware = self._create_malware(malware_args)
            self._append_SDO_without_refs(malware)
            object_refs.append(malware_id)
            self.__ids[cluster['uuid']] = malware_id
        return object_refs

    def _parse_malware_is_family_field(
            self, meta_args: dict, is_family: list | bool | int | str):
        if isinstance(is_family, list):
            is_family = is_family[0]
        feature = 'is_family'
        if self._version == '2.0':
            feature = f'x_misp_{feature}'
        meta_args[feature] = (
            is_family if isinstance(is_family, bool) else
            True if is_family in ('True', 'true', '1', 1) else False
        )

    def _parse_malware_parent_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_malware_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_malware_types(self, meta_args: dict, values: Union[list, str]):
        feature = 'malware_types' if self._version == '2.1' else 'labels'
        meta_args[feature] = values if isinstance(values, list) else [values]

    def _parse_meta_custom_fields(self, cluster_meta: dict) -> dict:
        meta_args = defaultdict(list)
        for key, values in cluster_meta.items():
            feature = self._mapping.external_references_fields(key)
            if feature is not None:
                self._parse_external_references(meta_args, values, feature)
            else:
                meta_args[f"x_misp_{self._sanitise_meta_field(key)}"] = values
        if any(key.startswith('x_misp_') for key in meta_args.keys()):
            meta_args['allow_custom'] = True
        return meta_args

    def _parse_meta_fields(
            self, cluster_meta: dict, object_type: str, value: str) -> dict:
        meta_args = defaultdict(list)
        mapping = f"{object_type.replace('-', '_')}_meta_mapping"
        for key, values in cluster_meta.items():
            if key in self._mapping.generic_meta_mapping(object_type):
                single = self._mapping.generic_meta_mapping(object_type)[key]
                if single and isinstance(values, list):
                    meta_args[key] = values[0]
                    continue
                meta_args[key] = values
                continue
            feature = self._mapping.external_references_fields(key)
            if feature is not None:
                self._parse_external_references(meta_args, values, feature)
                continue
            to_call = getattr(self._mapping, mapping)(key)
            if to_call is not None:
                args = [meta_args, values]
                if 'synonyms' in to_call:
                    args.append(value)
                getattr(self, to_call)(*args)
            else:
                meta_args[f"x_misp_{self._sanitise_meta_field(key)}"] = values
        if any(key.startswith('x_misp_') for key in meta_args.keys()):
            meta_args['allow_custom'] = True
        return meta_args

    def _parse_synonyms_21_meta_field(
            self, meta_args: dict, values: list, cluster_value: str):
        if not isinstance(values, list):
            values = [values]
        aliases = [value for value in values if value != cluster_value]
        if aliases:
            feature = 'aliases' if self._version == '2.1' else 'x_misp_synonyms'
            meta_args[feature] = aliases

    @staticmethod
    def _parse_synonyms_meta_field(
        meta_args: dict, values: list, cluster_value: str):
        if not isinstance(values, list):
            values = [values]
        aliases = [value for value in values if value != cluster_value]
        if aliases:
            meta_args['aliases'] = aliases

    def _parse_sector_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                             timestamp: Union[datetime, None]) -> list:
        object_refs = []
        ids = {}
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            sector_args = self._create_sector_galaxy_args(
                cluster, galaxy['description'], galaxy['name'], timestamp
            )
            sector = self._create_identity(sector_args)
            self._append_SDO_without_refs(sector)
            object_refs.append(sector.id)
            ids[cluster['uuid']] = sector.id
        self.populate_unique_ids(ids)
        return object_refs

    def _parse_sector_attribute_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                                       object_id: str, timestamp: datetime):
        object_refs = self._parse_sector_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_sector_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_sector_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _create_sector_galaxy_args(
            self, cluster: Union[MISPGalaxyCluster, dict], description: str,
            name: str, timestamp: datetime) -> dict:
        if cluster.get('description'):
            description = cluster['description']
        sector_args = {
            'id': f"identity--{cluster['uuid']}", 'type': 'identity',
            'name': cluster['value'], 'identity_class': 'class',
            'labels': self._create_galaxy_labels(name, cluster),
            'description': description, 'interoperability': True
        }
        if timestamp is None:
            if not cluster.get('timestamp'):
                return sector_args
            timestamp = self._datetime_from_timestamp(cluster['timestamp'])
        sector_args.update({'created': timestamp, 'modified': timestamp})
        return sector_args

    def _parse_threat_actor_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_threat_actor_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_threat_actor_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_threat_actor_galaxy(
            galaxy, self.event_timestamp
        )
        self._handle_object_refs(object_refs)

    def _parse_threat_actor_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            threat_actor_id = f"threat-actor--{cluster['uuid']}"
            threat_actor_args = self._create_galaxy_args(
                cluster, galaxy['name'], threat_actor_id, timestamp
            )
            threat_actor = self._create_threat_actor(threat_actor_args)
            self._append_SDO_without_refs(threat_actor)
            object_refs.append(threat_actor_id)
            self.__ids[cluster['uuid']] = threat_actor_id
        return object_refs

    def _parse_threat_actor_parent_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_threat_actor_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_threat_actor_types(
            self, meta_args: dict, values: Union[list, str]):
        feature = 'threat_actor_types' if self._version == '2.1' else 'labels'
        meta_args[feature] = values if isinstance(values, list) else [values]

    def _parse_tool_attribute_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                                     object_id: str, timestamp: datetime):
        object_refs = self._parse_tool_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_tool_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_tool_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _parse_tool_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                           timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            tool_id = f"tool--{cluster['uuid']}"
            tool_args = self._create_galaxy_args(
                cluster, galaxy['name'], tool_id, timestamp
            )
            tool = self._create_tool(tool_args)
            self._append_SDO_without_refs(tool)
            object_refs.append(tool_id)
            self.__ids[cluster['uuid']] = tool_id
        return object_refs

    def _parse_tool_parent_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_tool_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_tool_types(self, meta_args: dict, values: list):
        feature = 'tool_types' if self._version == '2.1' else 'labels'
        meta_args[feature] = values if isinstance(values, list) else [values]

    def _parse_undefined_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                                timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            custom_id = f"x-misp-galaxy-cluster--{cluster['uuid']}"
            custom_args = self._create_custom_galaxy_args(
                cluster, galaxy['name'], galaxy['description'],
                custom_id, timestamp
            )
            custom_galaxy = self._create_custom_galaxy(custom_args)
            self._append_SDO_without_refs(custom_galaxy)
            object_refs.append(custom_id)
            self.__ids[cluster['uuid']] = custom_id
        return object_refs

    def _parse_vulnerability_attribute_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            object_id: str, timestamp: datetime):
        object_refs = self._parse_vulnerability_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_vulnerability_event_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_vulnerability_galaxy(
            galaxy, self.event_timestamp
        )
        self._handle_object_refs(object_refs)

    def _parse_vulnerability_galaxy(
            self, galaxy: Union[MISPGalaxy, dict],
            timestamp: Optional[datetime] = None) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            vulnerability_id = f"vulnerability--{cluster['uuid']}"
            vulnerability_args = self._create_galaxy_args(
                cluster, galaxy['name'], vulnerability_id, timestamp
            )
            vulnerability = self._create_vulnerability(vulnerability_args)
            self._append_SDO_without_refs(vulnerability)
            object_refs.append(vulnerability_id)
            self.__ids[cluster['uuid']] = vulnerability_id
        return object_refs

    def _parse_vulnerability_parent_galaxy(
            self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_vulnerability_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    ############################################################################
    #                  STIX OBJECTS CREATION HELPER FUNCTIONS                  #
    ############################################################################

    @staticmethod
    def _create_attachment_args(value: str, data: str) -> dict:
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        return {
            'allow_custom': True, 'payload_bin': data, 'x_misp_filename': value
        }

    def _create_custom_galaxy_args(
            self, cluster: Union[MISPGalaxyCluster, dict],
            galaxy_name: str, description: str, custom_id: str,
            timestamp: Optional[datetime] = None) -> dict:
        custom_args = {
            'id': custom_id,
            'labels': self._create_galaxy_labels(galaxy_name, cluster),
            'x_misp_name': galaxy_name, 'x_misp_type': cluster['type'],
            'x_misp_value': cluster['value'],
            'x_misp_description': f"{description} | {cluster['description']}",
            'interoperability': True
        }
        if cluster.get('meta'):
            custom_args['x_misp_meta'] = {
                self._sanitise_meta_field(key): value for key, value
                in cluster['meta'].items()
            }
        if timestamp is None:
            if not cluster.get('timestamp'):
                return custom_args
            timestamp = self._datetime_from_timestamp(cluster['timestamp'])
        custom_args.update({'created': timestamp, 'modified': timestamp})
        return custom_args

    def _create_galaxy_args(
            self, cluster: Union[MISPGalaxyCluster, dict], name: str,
            object_id: str, timestamp: Optional[datetime] = None) -> dict:
        object_type = object_id.split('--')[0]
        value = cluster['value']
        if cluster['type'].startswith('mitre-') and ' - ' in value:
            value = value.split(' - ')[0].strip()
        galaxy_args = {
            'id': object_id, 'type': object_type, 'name': value,
            'labels': self._create_galaxy_labels(name, cluster),
            'interoperability': True
        }
        if cluster.get('description') is not None:
            galaxy_args['description'] = cluster['description']
        if timestamp is None:
            if not cluster.get('timestamp'):
                return galaxy_args
            timestamp = self._datetime_from_timestamp(cluster.pop('timestamp'))
        galaxy_args.update({'created': timestamp, 'modified': timestamp})
        if cluster.get('meta'):
            feature = f"{object_type.replace('-', '_')}_meta_mapping"
            meta_args = (
                self._parse_meta_fields(cluster['meta'], object_type, value)
                if hasattr(self._mapping, feature) else
                self._parse_meta_custom_fields(cluster['meta'])
            )
            if object_type in _labelled_object_types and 'labels' in meta_args:
                galaxy_args['labels'].extend(meta_args.pop('labels'))
            galaxy_args.update(meta_args)
        return galaxy_args

    @staticmethod
    def _create_galaxy_labels(galaxy_name: str, cluster: dict) -> list:
        labels = [
            f'misp:galaxy-name="{galaxy_name}"',
            f'misp:galaxy-type="{cluster["type"]}"'
        ]
        if cluster.get('tag_name'):
            labels.append(cluster['tag_name'])
        return labels

    @staticmethod
    def _create_killchain(category: str) -> list:
        kill_chain = [
            {'kill_chain_name': 'misp-category', 'phase_name': category}
        ]
        return kill_chain

    @staticmethod
    def _create_labels(attribute: Union[MISPAttribute, dict]) -> list:
        return [
            f'misp:{feature}="{attribute[feature]}"'
            for feature in _label_fields if attribute.get(feature)
        ]

    @staticmethod
    def _create_object_labels(misp_object: Union[MISPObject, dict],
                              to_ids: Optional[bool] = None) -> list:
        labels = [
            f'misp:name="{misp_object["name"].replace("|", "-")}"',
            f'misp:meta-category="{misp_object["meta-category"]}"'
        ]
        if to_ids is not None:
            labels.append(f'misp:to_ids="{to_ids}"')
        return labels

    def _handle_identity(self, identity_id: str, name: str):
        identity_args = {
            'id': identity_id, 'name': name, 'identity_class': 'organization'
        }
        identity = self._create_identity(identity_args)
        self.__objects.insert(self.__index, identity)
        self.__index += 1
        self.unique_ids[identity_id] = identity_id

    def _parse_contact_information(self, attributes: dict, name: str) -> list:
        contact_information = []
        for key in getattr(self._mapping, f"{name}_contact_info_fields")():
            if attributes.get(key):
                contact_information.append(
                    f"{key}: {'; '.join(attributes.pop(key))}"
                )
        return contact_information

    def _parse_identity_args(
            self, misp_object: Union[MISPObject, dict],
            identity_class: str) -> dict:
        identity_id = self._parse_stix_object_id(
            'object', 'identity', misp_object
        )
        timestamp = self._parse_timestamp_value(misp_object)
        identity_args = {
            'id': identity_id, 'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id,
            'identity_class': identity_class, 'interoperability': True,
            'labels': self._create_object_labels(
                misp_object,
                to_ids=self._fetch_ids_flag(misp_object['Attribute'])
            )
        }
        markings = self._handle_object_tags_and_galaxies(
            misp_object, identity_id, timestamp
        )
        if markings:
            self._handle_markings(identity_args, markings)
        return identity_args

    ############################################################################
    #                   OBSERVABLE OBJECT PARSING FUNCTIONS.                   #
    ############################################################################

    def _parse_account_args(self, attributes: list, name: str) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=getattr(self._mapping, f"{name}_single_fields")()
        )
        account_args = {'account_type': name.split('_')[0]}
        mapping = getattr(self._mapping, f"{name}_object_mapping")
        for key, feature in mapping().items():
            if attributes.get(key):
                account_args[feature] = attributes.pop(key)
        if attributes:
            account_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return account_args

    def _parse_account_with_attachment_args(
            self, object_attributes: list, name: str):
        attributes = self._extract_multiple_object_attributes_with_data(
            object_attributes,
            force_single=getattr(self._mapping, f"{name}_single_fields")(),
            with_data=getattr(self._mapping, f"{name}_data_fields")()
        )
        account_args = {'account_type': name.split('_')[0]}
        mapping = getattr(self._mapping, f"{name}_object_mapping")
        for key, feature in mapping().items():
            if attributes.get(key):
                account_args[feature] = attributes.pop(key)
        if attributes:
            account_args.update(
                self._handle_observable_multiple_properties_with_data(
                    attributes, name
                )
            )
        return account_args

    def _parse_android_app_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes, force_single=self._mapping.android_app_single_fields()
        )
        software_args = {}
        for key, feature in self._mapping.android_app_object_mapping().items():
            if attributes.get(key):
                software_args[feature] = attributes.pop(key)
        if attributes:
            software_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return software_args

    def _parse_AS_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes, force_single=self._mapping.as_single_fields()
        )
        as_args = {'number': self._parse_AS_value(attributes.pop('asn'))}
        if attributes.get('description'):
            as_args['name'] = attributes.pop('description')
        if attributes:
            as_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return as_args

    def _parse_cpe_asset_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes, force_single=self._mapping.cpe_asset_single_fields()
        )
        software_args = {}
        if attributes.get('language'):
            software_args['languages'] = attributes.pop('language')
        for key, feature in self._mapping.cpe_asset_object_mapping().items():
            if attributes.get(key):
                software_args[feature] = attributes.pop(key)
        if attributes:
            software_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return software_args

    def _parse_credential_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes, force_single=self._mapping.credential_single_fields()
        )
        credential_args = {}
        for key, feature in self._mapping.credential_object_mapping().items():
            if attributes.get(key):
                credential_args[feature] = self._select_single_feature(
                    attributes, key
                )
        if attributes:
            credential_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return credential_args

    def _parse_domain_args(self, attributes: dict) -> dict:
        domain_args = {}
        for feature in ('domain', 'hostname'):
            if attributes.get(feature):
                domain_args['value'] = self._select_single_feature(
                    attributes, feature
                )
                break
        if attributes:
            domain_args.update(self._handle_observable_properties(attributes))
        return domain_args

    def _parse_email_args(self, attributes: dict) -> dict:
        email_args = {}
        has_header = any(
            key in attributes for key
            in self._mapping.email_header_fields().keys()
        )
        if has_header:
            header_fields = {}
            for key, feature in self._mapping.email_header_fields().items():
                if attributes.get(key):
                    header_fields[feature] = self._select_single_feature(
                        attributes, key
                    )
            email_args['additional_header_fields'] = header_fields
        if attributes.get('send-date'):
            send_date = self._select_single_feature(attributes, 'send-date')
            if not isinstance(send_date, datetime):
                send_date = self._datetime_from_str(send_date)
            email_args['date'] = send_date
        for key, feature in self._mapping.email_observable_mapping().items():
            if attributes.get(key):
                email_args[feature] = self._select_single_feature(
                    attributes, key
                )
        if attributes:
            email_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return email_args

    def _parse_file_args(self, attributes: dict, misp_object: dict) -> dict:
        file_args = defaultdict(dict)
        for attribute_type in self._mapping.file_hash_main_types():
            value = attributes.get(attribute_type)
            if value is None:
                continue
            hash_type = self._define_hash_type(attribute_type)
            if self._check_hash_value(hash_type, value):
                file_args['hashes'][hash_type] = attributes.pop(attribute_type)
            else:
                self._invalid_object_hash_value_error(hash_type, misp_object)
        for attribute_type in self._mapping.file_hash_types():
            hash_type = self._define_hash_type(attribute_type)
            value = attributes.get(attribute_type)
            if value is None or hash_type in file_args['hashes']:
                continue
            if self._check_hash_value(hash_type, value):
                file_args['hashes'][hash_type] = attributes.pop(attribute_type)
            else:
                self._invalid_object_hash_value_error(hash_type, misp_object)
        for key, feature in self._mapping.file_object_mapping().items():
            if attributes.get(key):
                value = self._select_single_feature(attributes, key)
                file_args[feature] = value
        for key, feature in self._mapping.file_time_fields().items():
            if attributes.get(key):
                file_args[feature] = self._datetime_from_str(
                    self._select_single_feature(attributes, key)
                )
        if attributes:
            file_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return file_args

    def _parse_http_request_args(self, attributes: dict) -> dict:
        args = {'protocols': ['tcp', 'http']}
        extension = defaultdict(dict)
        extension_mapping = self._mapping.http_request_object_mapping(
            'request_extension'
        )
        for key, feature in extension_mapping.items():
            if attributes.get(key) and feature not in extension:
                extension[feature] = attributes.pop(key)
        field = 'request_header'
        header_mapping = self._mapping.http_request_object_mapping(field)
        for key, feature in header_mapping.items():
            if attributes.get(key):
                extension[field][feature] = self._select_single_feature(
                    attributes, key
                )
        if extension:
            args['extensions'] = {'http-request-ext': extension}
        if attributes:
            args.update(self._handle_observable_multiple_properties(attributes))
        return args

    def _parse_ip_port_args(self, attributes: dict, protocols: set) -> dict:
        args = {}
        if 'protocol' in attributes:
            protocols.add(attributes.pop('protocol'))
        args['protocols'] = list(protocols) if protocols else ['tcp']
        ip_port_mapping = self._mapping.ip_port_object_mapping('features')
        for key, feature in ip_port_mapping.items():
            if attributes.get(key):
                args[feature] = self._select_single_feature(attributes, key)
        timeline_mapping = self._mapping.ip_port_object_mapping('timeline')
        for key, feature in timeline_mapping.items():
            if attributes.get(key):
                args[feature] = self._datetime_from_str(attributes.pop(key))
        if attributes:
            args.update(self._handle_observable_multiple_properties(attributes))
        return args

    def _parse_lnk_args(self, attributes: dict, misp_object) -> dict:
        file_args = defaultdict(dict)
        if attributes.get('filename'):
            file_args['name'] = self._select_single_feature(
                attributes, 'filename')
        for attribute_type in self._mapping.lnk_hash_types():
            value = attributes.get(attribute_type)
            if value is None:
                continue
            hash_type = self._define_hash_type(attribute_type)
            if self._check_hash_value(hash_type, value):
                file_args['hashes'][hash_type] = attributes.pop(attribute_type)
            else:
                self._invalid_object_hash_value_error(hash_type, misp_object)
        for key, feature in self._mapping.lnk_object_mapping().items():
            if attributes.get(key):
                file_args[feature] = self._select_single_feature(
                    attributes, key
                )
        for key, feature in self._mapping.lnk_time_fields().items():
            if attributes.get(key):
                value = self._select_single_feature(attributes, key)
                file_args[feature] = self._datetime_from_str(value)
        if attributes:
            file_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return file_args

    def _parse_malware_sample_additional_fields(
            self, data: BytesIO | str) -> dict:
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        return {
            'payload_bin': data,
            **self._mapping.malware_sample_additional_observable_values()
        }

    def _parse_malware_sample_args(
            self, value: str, data: BytesIO | str) -> dict:
        args = {'allow_custom': True}
        for separator in self.composite_separators:
            if separator in value:
                filename, md5 = value.split(separator)
                if not self._check_hash_value('MD5', md5):
                    raise InvalidHashValueError()
                args.update(
                    {'hashes': {'MD5': md5}, 'x_misp_filename': filename}
                )
                break
        else:
            self._composite_attribute_value_warning('malware-sample', value)
            args['x_misp_filename'] = value
        args.update(self._parse_malware_sample_additional_fields(data))
        return args

    def _parse_malware_sample_custom_args(
            self, value: str, data: BytesIO | str) -> dict:
        args = {'allow_custom': True, 'x_misp_malware_sample': value}
        args.update(self._parse_malware_sample_additional_fields(data))
        return args

    def _parse_mutex_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        mutex_args = {}
        if attributes.get('name'):
            mutex_args['name'] = attributes.pop('name')
        if attributes:
            mutex_args.update(self._handle_observable_properties(attributes))
        return mutex_args

    def _parse_netflow_args(self, attributes: dict) -> dict:
        args = self._parse_netflow_protocol(attributes)
        netflow_mapping = self._mapping.netflow_object_mapping('features')
        for key, feature in netflow_mapping.items():
            if attributes.get(key):
                args[feature] = attributes.pop(key)
        timeline_mapping = self._mapping.netflow_object_mapping('timeline')
        for key, feature in timeline_mapping.items():
            if attributes.get(key):
                args[feature] = self._datetime_from_str(attributes.pop(key))
        if attributes:
            args.update(self._handle_observable_properties(attributes))
        return args

    @staticmethod
    def _parse_netflow_protocol(attributes: dict) -> dict:
        protocols = set()
        extensions = defaultdict(dict)
        if attributes.get('icmp-type'):
            extensions['icmp-ext']['icmp_tpye_hex'] = attributes.pop(
                'icmp-type'
            )
            protocols.add('icmp')
        if attributes.get('tcp-flags'):
            extensions['tcp-ext']['src_flags_hex'] = attributes.pop('tcp-flags')
            protocols.add('tcp')
        if attributes.get('protocol'):
            protocols.add(attributes.pop('protocol').lower())
        if extensions:
            return {'extensions': extensions, 'protocols': list(protocols)}
        if protocols:
            return {'protocols': list(protocols)}
        return {'protocols': ['ip']}

    def _parse_network_connection_args(self, attributes: dict) -> dict:
        network_traffic_args = {}
        network_mapping = self._mapping.network_connection_mapping('features')
        for key, feature in network_mapping.items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        protocols = []
        for key in self._mapping.network_connection_mapping('protocols'):
            if attributes.get(key):
                protocols.append(attributes.pop(key).lower())
        if not protocols:
            protocols.append('tcp')
        network_traffic_args['protocols'] = protocols
        if attributes:
            network_traffic_args.update(
                self._handle_observable_properties(attributes)
            )
        return network_traffic_args

    def _parse_network_socket_args(self, attributes: dict) -> dict:
        network_traffic_args = defaultdict(dict)
        socket_mapping = self._mapping.network_socket_mapping('features')
        for key, feature in socket_mapping.items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        network_traffic_args['protocols'] = (
            [attributes.pop('protocol').lower()]
            if attributes.get('protocol') else ['tcp']
        )
        family_in_enum = (
            attributes.get('address-family')
            in self._mapping.address_family_enum_list()
        )
        if family_in_enum:
            socket_ext = {}
            extension_mapping = self._mapping.network_socket_mapping(
                'extension'
            )
            for key, field in extension_mapping.items():
                if attributes.get(key):
                    value = attributes.pop(key)
                    feature = key.replace('-', '_')
                    if value in getattr(self._mapping, f"{feature}_enum_list")():
                        socket_ext[field] = value
                    else:
                        network_traffic_args[f'x_misp_{feature}'] = value
            if attributes.get('state'):
                for state in attributes.pop('state'):
                    if state in self._mapping.network_socket_state_fields():
                        socket_ext[f'is_{state}'] = True
                    else:
                        attributes['state'].append(state)
            network_traffic_args['extensions']['socket-ext'] = socket_ext
        if attributes:
            network_traffic_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return network_traffic_args

    def _parse_process_args(self, attributes: dict, level: str) -> dict:
        process_args = {}
        for key, feature in self._mapping.process_object_mapping(level).items():
            if attributes.get(key):
                process_args[feature] = attributes.pop(key)
        if attributes:
            process_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        return process_args

    def _parse_registry_key_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        registry_key_args = self._parse_regkey_key_values_observable(attributes)
        values_args = {}
        if attributes.get('data'):
            values_args['data'] = attributes.pop('data')
        for key, feature in self._mapping.registry_key_mapping().items():
            if attributes.get(key):
                values_args[feature] = attributes.pop(key)
        if values_args:
            registry_key_args['values'] = [values_args]
        if attributes:
            registry_key_args.update(
                self._handle_observable_properties(attributes)
            )
        return registry_key_args

    def _parse_url_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        url_args = {}
        if attributes.get('url'):
            url_args['value'] = attributes.pop('url')
        if attributes:
            url_args.update(self._handle_observable_properties(attributes))
        return url_args

    def _parse_user_account_args(self, attributes: dict) -> dict:
        attributes = self._extract_multiple_object_attributes_with_data(
            attributes,
            force_single=self._mapping.user_account_single_fields(),
            with_data=self._mapping.user_account_data_fields()
        )
        user_account_args = {}
        account_mapping = self._mapping.user_account_object_mapping('features')
        for key, feature in account_mapping.items():
            if attributes.get(key):
                user_account_args[feature] = attributes.pop(key)
        timeline_mapping = self._mapping.user_account_object_mapping('timeline')
        for key, feature in timeline_mapping.items():
            if attributes.get(key):
                timestamp = attributes.pop(key)
                if not isinstance(timestamp, datetime):
                    timestamp = self._datetime_from_str(timestamp)
                user_account_args[feature] = timestamp
        extension = {}
        extension_mapping = self._mapping.user_account_object_mapping(
            'extension'
        )
        for key, feature in extension_mapping.items():
            if attributes.get(key):
                extension[feature] = attributes.pop(key)
        if extension:
            user_account_args['extensions'] = {'unix-account-ext': extension}
        if attributes:
            user_account_args.update(
                self._handle_observable_multiple_properties_with_data(
                    attributes, 'user_account'
                )
            )
        return user_account_args

    def _parse_x509_args(self, misp_object: Union[MISPObject, dict]) -> dict:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.x509_single_fields()
        )
        x509_args = defaultdict(dict)
        if attributes.get('self_signed'):
            x509_args['is_self_signed'] = attributes.pop('self_signed')
        for feature in self._mapping.x509_hash_fields():
            value = attributes.get(feature)
            if value is None:
                continue
            hash_type = self._define_hash_type(feature.split('-')[-1])
            if self._check_hash_value(hash_type, value):
                x509_args['hashes'][hash_type] = attributes.pop(feature)
            else:
                self._invalid_object_hash_value_error(hash_type, misp_object)
        x509_mapping = self._mapping.x509_object_mapping('features')
        for key, feature in x509_mapping.items():
            if attributes.get(key):
                x509_args[feature] = attributes.pop(key)
        timeline_mapping = self._mapping.x509_object_mapping('timeline')
        for key, feature in timeline_mapping.items():
            if attributes.get(key):
                timestamp = attributes.pop(key)
                if not isinstance(timestamp, datetime):
                    timestamp = self._datetime_from_str(timestamp)
                x509_args[feature] = timestamp
        extension = []
        extension_mapping = self._mapping.x509_object_mapping('extension')
        for key, feature in extension_mapping.items():
            if attributes.get(key):
                for value in attributes.pop(key):
                    extension.append(f"{feature}:{value}")
        if extension:
            name = ','.join(extension)
            x509_args['x509_v3_extensions']['subject_alternative_name'] = name
        if attributes:
            x509_args.update(self._handle_observable_properties(attributes))
        return x509_args

    ############################################################################
    #                       PATTERNS CREATION FUNCTIONS.                       #
    ############################################################################

    def _create_AS_pattern(self, number: str) -> str:
        return f"autonomous-system:number = '{self._parse_AS_value(number)}'"

    @staticmethod
    def _create_content_ref_pattern(
            value: str, feature: str = 'payload_bin') -> str:
        return f"file:content_ref.{feature} = '{value}'"

    @staticmethod
    def _create_domain_pattern(domain: str) -> str:
        return f"domain-name:value = '{domain}'"

    @staticmethod
    def _create_domain_resolving_pattern(value: str) -> str:
        return f"domain-name:resolves_to_refs[*].value = '{value}'"

    def _create_filename_hash_pattern(
            self, hash_type: str, attribute_value: str, separator: str) -> str:
        filename, hash_value = attribute_value.split(separator)
        filename_pattern = self._create_filename_pattern(filename)
        hash_pattern = self._create_hash_pattern(hash_type, hash_value)
        return f"{filename_pattern} AND {hash_pattern}"

    @staticmethod
    def _create_filename_pattern(name: str) -> str:
        return f"file:name = '{name}'"

    def _create_hash_pattern(self, attribute_type: str, value: str,
                             prefix: Optional[str] = 'file:hashes') -> str:
        value = value.strip('"').strip("'").strip('\\')
        hash_type = self._define_hash_type(attribute_type)
        if not self._check_hash_value(hash_type, value):
            raise InvalidHashValueError()
        return f"{prefix}.{hash_type} = '{value}'"

    def _create_ip_pattern(self, ip_type: str, value: str) -> str:
        address_type = self._define_address_type(value)
        network_type = f"network-traffic:{ip_type}_ref.type = '{address_type}'"
        network_value = f"network-traffic:{ip_type}_ref.value = '{value}'"
        return f"{network_type} AND {network_value}"

    @staticmethod
    def _create_port_pattern(port: str, ip_type: str = 'dst') -> str:
        return f"network-traffic:{ip_type}_port = '{port}'"

    @staticmethod
    def _create_regkey_pattern(key: str) -> str:
        return f"windows-registry-key:key = '{key}'"

    def _handle_patterning_object_indicator(
            self, misp_object: Union[MISPObject, dict], indicator_args: dict):
        indicator_id = self._parse_stix_object_id(
            'object', 'indicator', misp_object
        )
        indicator_args.update(
            {
                'id': indicator_id, 'type': 'indicator', 'allow_custom': True,
                'labels': self._create_object_labels(misp_object, to_ids=True),
                'created_by_ref': self.identity_id, 'interoperability': True,
                'kill_chain_phases': self._create_killchain(
                    misp_object['meta-category']
                )
            }
        )
        indicator_args.update(self._handle_indicator_time_fields(misp_object))
        markings = self._handle_object_tags_and_galaxies(
            misp_object, indicator_id, indicator_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'], indicator_id,
                indicator_args['modified']
            )
        indicator = self._create_indicator(indicator_args)
        getattr(self, self._results_handling_function)(indicator)
        self._handle_object_analyst_data(indicator, misp_object)

    ############################################################################
    #                            UTILITY FUNCTIONS.                            #
    ############################################################################

    @staticmethod
    def _check_hash_value(attribute_type, value):
        hash_type = attribute_type.upper()
        return not hasattr(Hash, hash_type) or check_hash(
            getattr(Hash, hash_type), value
        )

    @staticmethod
    def _clean_custom_properties(custom_args: dict):
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(custom_args['labels'], True)
        if custom_args.get('markings'):
            stix_markings = ListProperty(StringProperty)
            stix_markings.clean(custom_args['markings'])

    @staticmethod
    def _define_address_type(address):
        if ':' in address:
            return 'ipv6-addr'
        return 'ipv4-addr'

    @staticmethod
    def _define_hash_type(hash_type: str) -> str:
        if '/' in hash_type:
            return f"SHA{hash_type.split('/')[1]}"
        return hash_type.replace('-', '').upper()

    @staticmethod
    def _extract_parent_process_attributes(attributes: dict) -> dict:
        parent_fields = tuple(
            key for key in attributes.keys() if key.startswith('parent-')
        )
        return {key: attributes.pop(key) for key in parent_fields}

    def _fetch_domain_ip_object_case(self, attributes: list) -> str:
        any_domain = any(
            attribute['object_relation'] in ('domain', 'hostname')
            for attribute in attributes
        )
        if not any_domain:
            return 'exception'
        for attribute in attributes:
            custom = (
                attribute['object_relation'] not in
                self._mapping.domain_ip_standard_fields()
            )
            if custom:
                return 'custom'
        return 'standard'

    def _fetch_included_reference_uuids(
            self, references: list, name: str) -> list:
        uuids = []
        for reference in references:
            if self._is_reference_included(reference, name):
                referenced_uuid = reference['referenced_uuid']
                if referenced_uuid not in self._objects_to_parse[name]:
                    self._referenced_object_name_warning(name, referenced_uuid)
                    continue
                uuids.append(referenced_uuid)
        return uuids

    def _find_target_uuid(self, reference: str) -> Union[str, None]:
        for object_ref in self.object_refs:
            if reference in object_ref:
                return object_ref

    @staticmethod
    def _get_matching_email_display_name(
            display_names: list, address: str) -> Optional[int]:
        # Trying first to get a perfect match in case of a very standard first name last name case
        for index, name in enumerate(display_names):
            display_name = name.lower().split(' ')
            if all(value in address for value in display_name):
                return index
        # Trying to get a potential match otherwise
        values = re.sub('[_.@-]', ' ', address.lower()).split(' ')
        for index, name in enumerate(display_names):
            display_name = name.lower()
            if any(value in display_name for value in values):
                return index
            initials = ''.join(value[0] for value in display_name.split(' '))
            if len(initials) > 1 and initials in address:
                return index
        # If no match, then the remaining unmatched display names are just going to be exported as custom property

    @staticmethod
    def _get_vulnerability_references(vulnerability: str) -> dict:
        return {'source_name': 'cve', 'external_id': vulnerability}

    def _handle_analyst_time_fields(self, stix_object: _STIX_OBJECT_TYPING,
                                    misp_object: Union[MISPNote, MISPOpinion]):
        for feature in ('created', 'modified'):
            if misp_object.get(feature):
                yield feature, self._datetime_from_str(misp_object[feature])
                continue
            yield feature, stix_object[feature]

    def _handle_custom_data_field(
            self, values: Union[list, str, tuple]) -> Union[dict, list, str]:
        if isinstance(values, list):
            if len(values) > 1:
                return [
                    self._parse_custom_data_value(value) for value in values
                ]
            return self._parse_custom_data_value(values[0])
        return self._parse_custom_data_value(values)

    @staticmethod
    def _handle_custom_data_pattern(
            prefix: str, key: str, value: Union[str, tuple]) -> list:
        if isinstance(value, tuple):
            value, data = value
            if not isinstance(data, str):
                data = b64encode(data.getvalue()).decode()
            return [
                f"{prefix}:x_misp_{key}.data = '{data}'",
                f"{prefix}:x_misp_{key}.value = '{value}'"
            ]
        return [f"{prefix}:x_misp_{key} = '{value}'"]

    def _handle_indicator_time_fields(
            self, data_layer: Union[MISPAttribute, MISPObject, dict]) -> dict:
        timestamp = self._parse_timestamp_value(data_layer)
        time_fields = {
            'created': timestamp, 'modified': timestamp, 'valid_from': timestamp
        }
        stix_fields = _stix_time_fields['indicator']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            if data_layer.get(misp_field):
                time_fields[stix_field] = self._datetime_from_str(
                    data_layer[misp_field]
                )
        invalid_time = (
            time_fields.get('valid_until')
            and time_fields['valid_from'] >= time_fields['valid_until']
        )
        if invalid_time:
            del time_fields['valid_until']
        return time_fields

    def _handle_observable_time_fields(
            self, data_layer: Union[MISPAttribute, MISPObject, dict]) -> dict:
        timestamp = self._parse_timestamp_value(data_layer)
        time_fields = {'created': timestamp, 'modified': timestamp}
        stix_fields = _stix_time_fields['observed-data']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            time_fields[stix_field] = (
                self._datetime_from_str(data_layer[misp_field])
                if data_layer.get(misp_field) else timestamp
            )
        if time_fields['first_observed'] > time_fields['last_observed']:
            if data_layer.get('last_seen'):
                time_fields['first_observed'] = time_fields['last_observed']
            else:
                time_fields['last_observed'] = time_fields['first_observed']
        return time_fields

    def _handle_value_for_pattern(self, attribute_value: str) -> str:
        # return attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
        if not isinstance(attribute_value, str):
            return attribute_value
        sanitized = self._sanitize_registry_key_value(attribute_value)
        return sanitized.replace("'", "\\'").replace('"', '\\\\"')

    @staticmethod
    def _parse_custom_data_value(
            value_to_parse: Union[str, tuple]) -> Union[dict, str]:
        if isinstance(value_to_parse, tuple):
            value, data = value_to_parse
            if not isinstance(data, str):
                data = b64encode(data.getvalue()).decode()
            return {'value': value, 'data': data}
        return value_to_parse

    def _parse_email_display_names(
            self, attributes: dict, feature: str) -> dict:
        display_feature = f'{feature}-display-name'
        display_names = {}
        if attributes.get(display_feature):
            for value in attributes[feature]:
                if isinstance(value, tuple):
                    value = value[0]
                index = self._get_matching_email_display_name(
                    attributes[display_feature], value
                )
                if index is not None:
                    display_names[value] = attributes[display_feature].pop(
                        index
                    )
                if not attributes[display_feature]:
                    del attributes[display_feature]
                    break
        return display_names

    def _parse_galaxy_relationship(
            self, source_id: str, target_id: str, relationship_type: str,
            timestamp: datetime):
        self.__relationships.append(
            {
                'source_ref': source_id, 'target_ref': target_id,
                'relationship_type': relationship_type,
                'created': timestamp, 'modified': timestamp,
                'allow_custom': True, 'interoperability': True
            }
        )

    def _parse_stix_object_id(self, feature: str, object_type: str,
                              misp_object: Union[dict, MISPObject]) -> str:
        return getattr(self, self._id_parsing_function[feature])(
            object_type, misp_object
        )

    def _parse_object_relationships(
            self, references: list, source_id: str, timestamp: datetime):
        for reference in references:
            referenced = reference['referenced_uuid']
            reference_to_parse = any(
                referenced in objects
                for objects in self._objects_to_parse.values()
            )
            if reference_to_parse:
                continue
            relationship = {
                'source_ref': source_id, 'undefined_target_ref': referenced,
                'relationship_type': reference['relationship_type'],
                'allow_custom': True, 'interoperability': True
            }
            if reference.get('timestamp'):
                reference_timestamp = self._datetime_from_timestamp(
                    reference['timestamp']
                )
                relationship.update(
                    {
                        'created': reference_timestamp,
                        'modified': reference_timestamp
                    }
                )
            else:
                relationship.update(
                    {'created': timestamp, 'modified': timestamp}
                )
            self.__relationships.append(relationship)

    def _parse_timestamp_value(
            self, misp_data_layer: _MISP_DATA_LAYER) -> datetime:
        if misp_data_layer.get('timestamp') is not None:
            return self._datetime_from_timestamp(misp_data_layer['timestamp'])
        return datetime.now(UTC)

    @staticmethod
    def _sanitise_meta_field(key: str, strict: Optional[bool] = False) -> str:
        for special_character in _special_characters:
            if special_character in key:
                key = key.replace(special_character, '_')
        if strict and '-' in key:
            return key.replace('-', '_')
        return key

    def _sanitize_registry_key_value(self, value: str) -> str:
        sanitized = self._sanitize_value(value.strip()).replace('\\', '\\\\')
        if '%' not in sanitized or '\\\\%' in sanitized:
            return sanitized
        if '\\%' in sanitized:
            return sanitized.replace('\\%', '\\\\%')
        return sanitized.replace('%', '\\\\%')

    def _sanitize_value(self, value: str) -> str:
        for character in ('"', "'"):
            if value.startswith(character):
                return self._sanitize_value(value[1:])
            if value.endswith(character):
                return self._sanitize_value(value[:-1])
        return value

    def _select_pe_object(self, pe_uuid: str) -> dict:
        to_ids, pe_object = self._objects_to_parse['pe'][pe_uuid]
        self._objects_to_parse['pe'][pe_uuid] = to_ids
        return pe_object
