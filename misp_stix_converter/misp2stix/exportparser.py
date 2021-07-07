# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
from .stix1_mapping import galaxy_types_mapping as stix1_galaxy_mapping
from .stix2_mapping import galaxy_types_mapping as stix2_galaxy_mapping
from collections import defaultdict
from datetime import datetime
from stix.indicator import Indicator
from typing import Optional


class MISPtoSTIXParser():
    __published_fields = ('published', 'publish_timestamp')

    def __init__(self):
        super().__init__()
        self._errors = []
        self._warnings = set()

    ################################################################################
    #                           COMMON PARSING FUNCTIONS                           #
    ################################################################################

    @staticmethod
    def _extract_multiple_object_attributes(attributes: list, force_single: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if force_single is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                if relation in force_single:
                    attributes_dict[relation] = attribute['value']
                else:
                    attributes_dict[relation].append(attribute['value'])
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(attribute['value'])
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_data(attributes: list, force_single: tuple = (), with_data: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            value = attribute['value']
            if relation in with_data and attribute.get('data'):
                value = (value, attribute['data'])
            if relation in force_single:
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_uuid(attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if with_uuid is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                value = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
                attributes_dict[relation].append(value)
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(
                (
                    attribute['value'],
                    attribute['uuid']
                )
            )
        return attributes_dict

    @staticmethod
    def _extract_object_attributes(attributes: list) -> dict:
        return {attribute['object_relation']: attribute['value'] for attribute in attributes}

    @staticmethod
    def _extract_object_attributes_with_uuid(attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        if with_uuid is not None:
            attributes_dict = {}
            for attribute in attributes:
                relation = attribute['object_relation']
                attributes_dict[relation] = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
            return attributes_dict
        return {attribute['object_relation']: (attribute['value'], attribute['uuid']) for attribute in attributes}

    def _extract_object_attribute_tags_and_galaxies(self, misp_object: dict, mapping: str) -> tuple:
        tags = set()
        galaxies = {}
        for attribute in misp_object['Attribute']:
            if attribute.get('Galaxy'):
                for galaxy in attribute['Galaxy']:
                    galaxy_type = galaxy['type']
                    if galaxy_type not in globals()[mapping]:
                        self._warnings.add(f"{galaxy_type} galaxy in {misp_object['name']} object not mapped.")
                        continue
                    if galaxy_type in galaxies:
                        self._merge_galaxy_clusters(galaxies[galaxy_type], galaxy)
                    else:
                        galaxies[galaxy_type] = galaxy
            if attribute.get('Tag'):
                tags.update(tag['name'] for tag in attribute['Tag'])
        return tags, galaxies

    def _handle_event_tags_and_galaxies(self, mapping: str) -> tuple:
        if self._misp_event.get('Galaxy'):
            tag_names = []
            for galaxy in self._misp_event['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in globals()[mapping]:
                    to_call = globals()[mapping][galaxy_type]
                    getattr(self, to_call.format('event'))(galaxy)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._warnings.add(f'{galaxy_type} galaxy in event not mapped.')
            return tuple(tag['name'] for tag in self._misp_event.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in self._misp_event.get('Tag', []))

    ################################################################################
    #                           COMMON UTILITY FUNCTIONS                           #
    ################################################################################

    @staticmethod
    def _datetime_from_timestamp(timestamp: str) -> datetime:
        return datetime.utcfromtimestamp(int(timestamp))

    def _is_published(self) -> bool:
        return all(self._misp_event.get(feature) for feature in self.__published_fields)

    @staticmethod
    def _merge_galaxy_clusters(galaxies: dict, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            for galaxy_cluster in galaxies['GalaxyCluster']:
                if cluster['uuid'] == galaxy_cluster['uuid']:
                    break
            else:
                galaxies['GalaxyCluster'].append(cluster)

    @staticmethod
    def _quick_fetch_tag_names(galaxy: dict) -> tuple:
        return tuple(f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"' for cluster in galaxy["GalaxyCluster"])

    @staticmethod
    def _select_single_feature(attributes: dict, feature: str) -> str:
        if isinstance(attributes[feature], list):
            if len(attributes[feature]) == 1:
                return attributes.pop(feature)[0]
            return attributes[feature].pop(0)
        return attributes.pop(feature)
