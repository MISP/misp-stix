# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
from . import stix1_mapping
from datetime import datetime
from stix.indicator import Indicator
from typing import Union


class ExportParser():
    def __init__(self):
        super().__init__()

    def load_file(self, filename):
        with open(filename, 'rt', encoding='utf-8') as f:
            self.json_event = json.loads(f.read())
        self.filename = filename


class MISPtoSTIXParser():
    __published_fields = ('published', 'publish_timestamp')

    def __init__(self):
        super().__init__()
        self._errors = []
        self._warnings = set()

    ################################################################################
    #                           COMMON PARSING FUNCTIONS                           #
    ################################################################################

    def _handle_event_tags_and_galaxies(self) -> tuple:
        if self._misp_event.get('Galaxy'):
            tag_names = []
            for galaxy in self._misp_event['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in stix1_mapping.galaxy_types_mapping:
                    to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
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
