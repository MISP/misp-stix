#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..misp_stix_mapping import Mapping
from .stix2_mapping import STIX2toMISPMapping
from typing import Union


class InternalSTIX2toMISPMapping(STIX2toMISPMapping):
    __stix_object_loading_mapping = Mapping(
        **{
            'note': '_load_note',
            'opinion': '_load_opinion',
            'x-misp-analyst-note': '_load_analyst_note',
            'x-misp-analyst-opinion': '_load_analyst_opinion',
            'x-misp-attribute': '_load_custom_attribute',
            'x-misp-event-report': '_load_note',
            'x-misp-galaxy-cluster': '_load_custom_galaxy_cluster',
            'x-misp-object': '_load_custom_object',
            'x-misp-opinion': '_load_custom_opinion',
            **STIX2toMISPMapping.stix_object_loading_mapping()
        }
    )

    @classmethod
    def stix_object_loading_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_object_loading_mapping.get(field)
