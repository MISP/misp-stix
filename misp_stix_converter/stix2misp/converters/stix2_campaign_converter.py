#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import ExternalSTIX2Converter, InternalSTIX2Converter
from .stix2mapping import ExternalSTIX2Mapping, InternalSTIX2Mapping
from pymisp import MISPGalaxyCluster
from stix2.v20.sdo import Campaign as Campaign_v20
from stix2.v21.sdo import Campaign as Campaign_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_CAMPAIGN_TYPING = Union[
    Campaign_v20, Campaign_v21
]


class STIX2CampaignMapping(ExternalSTIX2Mapping):
    __campaign_meta_mapping = Mapping(
        aliases='synonyms',
        first_seen='first_seen',
        last_seen='last_seen',
        objective='objective'
    )

    @classmethod
    def campaign_meta_mapping(cls) -> dict:
        return cls.__campaign_meta_mapping


class ExternalSTIX2CampaignConverter(ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = STIX2CampaignMapping

    def parse(self, campaign_ref: str):
        campaign = self.main_parser._get_stix_object(campaign_ref)
        self._parse_galaxy(campaign)

    def _create_cluster(self, campaign: _CAMPAIGN_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        campaign_args = self._create_cluster_args(
            campaign, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(campaign)
        if hasattr(campaign, 'external_references'):
            meta.update(
                self._handle_external_references(campaign.external_references)
            )
        if meta:
            campaign_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(**campaign_args)


class InternalSTIX2CampaignConverter(InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = InternalSTIX2Mapping

    def parse(self, campaign_ref: str):
        campaign = self.main_parser._get_stix_object(campaign_ref)
        attribute = self._create_attribute_dict(campaign)
        attribute['value'] = campaign.name
        self.main_parser._add_misp_attribute(attribute, campaign)
