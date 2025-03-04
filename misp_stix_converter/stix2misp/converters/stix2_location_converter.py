#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter,
    _MAIN_PARSER_TYPING)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPGalaxyCluster
from stix2.v21.sdo import Location
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser


class STIX2LocationMapping(STIX2Mapping, metaclass=ABCMeta):
    __accuracy_radius_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'accuracy-radius'}
    )
    __location_object_mapping = Mapping(
        city={'type': 'text', 'object_relation': 'city'},
        country={'type': 'text', 'object_relation': 'countrycode'},
        description=STIX2Mapping.text_attribute(),
        latitude={'type': 'float', 'object_relation': 'latitude'},
        longitude={'type': 'float', 'object_relation': 'longitude'},
        postal_code={'type': 'text', 'object_relation': 'zipcode'},
        region={'type': 'text', 'object_relation': 'region'},
        street_address={'type': 'text', 'object_relation': 'address'}
    )

    @classmethod
    def accuracy_radius_attribute(cls) -> dict:
        return cls.__accuracy_radius_attribute

    @classmethod
    def location_object_mapping(cls) -> dict:
        return cls.__location_object_mapping


class STIX2LocationConverter(STIX2Converter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)

    def _parse_location_object(self, location: Location):
        misp_object = self._create_misp_object('geolocation', location)
        if hasattr(location, 'description'):
            misp_object.comment = location.description
        for attribute in self._generic_parser(location):
            misp_object.add_attribute(**attribute)
        if hasattr(location, 'precision'):
            misp_object.add_attribute(
                **{
                    'value': float(location.precision) / 1000,
                    **self._mapping.accuracy_radius_attribute()
                }
            )
        self.main_parser._add_misp_object(misp_object, location)


class ExternalSTIX2LocationMapping(
        STIX2LocationMapping, ExternalSTIX2Mapping):
    __location_meta_mapping = Mapping(
        administrative_area='administrative_area',
        country='country',
        region='region',
    )
    __location_object_fields = (
        'city', 'latitude', 'longitude', 'postal_code', 'street_address'
    )

    @classmethod
    def location_meta_mapping(cls) -> dict:
        return cls.__location_meta_mapping

    @classmethod
    def location_object_fields(cls) -> tuple:
        return cls.__location_object_fields


class ExternalSTIX2LocationConverter(
        STIX2LocationConverter, ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2LocationMapping

    def parse(self, location_ref: str):
        location = self.main_parser._get_stix_object(location_ref)
        if self._is_geolocation_object(location):
            self._parse_location_object(location)
        else:
            self._parse_galaxy(location)

    def _create_cluster(
            self, location: Location, description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        location_args = self._create_cluster_args(
            location, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(location)
        if hasattr(location, 'external_references'):
            meta.update(
                self._handle_external_references(
                    location.external_references
                )
            )
        if hasattr(location, 'labels'):
            self._handle_labels(meta, location.labels)
        if meta:
            location_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(**location_args)


    def _is_geolocation_object(self, location: Location) -> bool:
        for field in self._mapping.location_object_fields():
            if hasattr(location, field):
                return True
        return False

class InternalSTIX2LocationMapping(
        STIX2LocationMapping, InternalSTIX2Mapping):
    __location_object_mapping = Mapping(
        **{
            **STIX2LocationMapping.location_object_mapping(),
            'x_misp_altitude': {'type': 'float', 'object_relation': 'altitude'},
            'x_misp_country': {'type': 'text', 'object_relation': 'country'},
            'x_misp_epsg': {'type': 'text', 'object_relation': 'epsg'},
            'x_misp_first_seen': InternalSTIX2Mapping.first_seen_attribute,
            'x_misp_last_seen': InternalSTIX2Mapping.last_seen_attribute,
            'x_misp_neighborhood': {
                'type': 'text', 'object_relation': 'neighborhood'
            },
            'x_misp_spacial_reference': {
                'type': 'text', 'object_relation': 'spacial-reference'
            }
        }
    )
    __regions_mapping = Mapping(
        **{
            'world': '001 - World',
            'africa': '002 - Africa',
            'eastern-africa': '014 - Eastern Africa',
            'middle-africa': '017 - Middle Africa',
            'northern-africa': '015 - Northern Africa',
            'southern-africa': '018 - Southern Africa',
            'western-africa': '011 - Western Africa',
            'americas': '019 - Americas',
            'caribbean': '029 - Caribbean',
            'central-america': '013 - Central America',
            'latin-america-caribbean': '419 - Latin America and the Caribbean',
            'northern-america': '021 - Northern America',
            'south-america': '005 - South America',
            'asia': '142 - Asia',
            'central-asia': '143 - Central Asia',
            'eastern-asia': '030 - Eastern Asia',
            'southern-asia': '034 - Southern Asia',
            'south-eastern-asia': '035 - South-eastern Asia',
            'western-asia': '145 - Western Asia',
            'europe': '150 - Europe',
            'eastern-europe': '151 - Eastern Europe',
            'northern-europe': '154 - Northern Europe',
            'southern-europe': '039 - Southern Europe',
            'western-europe': '155 - Western Europe',
            'oceania': '009 - Oceania',
            'antarctica': '010 - Antarctica',
            'australia-new-zealand': '053 - Australia and New Zealand',
            'melanesia': '054 - Melanesia',
            'micronesia': '057 - Micronesia',
            'polynesia': '061 - Polynesia'
        }
    )

    @classmethod
    def location_object_mapping(cls) -> dict:
        return cls.__location_object_mapping

    @classmethod
    def regions_mapping(cls, field: str, default_value: str) -> str:
        return cls.__regions_mapping.get(field, default_value)


class InternalSTIX2LocationConverter(
        STIX2LocationConverter, InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2LocationMapping

    def parse(self, location_ref: str):
        location = self.main_parser._get_stix_object(location_ref)
        feature = self._handle_mapping_from_labels(location.labels, location.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(location)
        except Exception as exception:
            _traceback = self.main_parser._parse_traceback(exception)
            self.main_parser._add_error(
                'Error while parsing the Location object with id '
                f'{location.id}: {_traceback}'
            )

    def _create_cluster(
            self, location: Location, description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        location_args = self._create_cluster_args(
            location, galaxy_type, description=description,
            cluster_value=(
                location.name if galaxy_type == 'country' or
                not hasattr(location, 'region') else
                self._mapping.regions_mapping(location.region, location.name)
            )
        )
        meta = self._handle_meta_fields(location)
        if meta:
            location_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(**location_args)
