#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import InternalSTIX2Converter
from .stix2mapping import InternalSTIX2Mapping
from pymisp import MISPEventReport
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_attribute_additional_fields = (
    'category', 'comment', 'data', 'to_ids', 'uuid'
)
_CUSTOM_OBJECT_TYPING = Union[
    CustomObject_v20, CustomObject_v21
]


class STIX2CustomObjectMapping(InternalSTIX2Mapping):
    __custom_object_mapping = Mapping(
        **{
            'x-misp-attribute': '_parse_custom_attribute',
            'x-misp-event-report': '_parse_custom_event_report',
            'x-misp-galaxy-cluster': '_parse_custom_galaxy_cluster',
            'x-misp-object': '_parse_custom_object'
        }
    )

    @classmethod
    def custom_object_mapping(cls, field: str) -> Union[str, None]:
        return cls.__custom_object_mapping.get(field)


class STIX2CustomObjectConverter(InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = STIX2CustomObjectMapping

    def parse(self, custom_ref: str):
        custom_object = self.main_parser._get_stix_object(custom_ref)
        feature = self._mapping.custom_object_mapping(custom_object.type)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(custom_object)
        except Exception as exception:
            _traceback = self.main_parser._parse_traceback(exception)
            self.main_parser._add_error(
                'Error parsing the Custom object with id '
                f'{custom_object.id}: {_traceback}'
            )

    def _parse_custom_attribute(self, custom_attribute: _CUSTOM_OBJECT_TYPING):
        attribute = {
            "type": custom_attribute.x_misp_type,
            "timestamp": self._timestamp_from_date(custom_attribute.modified),
            "value": self._sanitise_value(custom_attribute.x_misp_value)
        }
        for field in _attribute_additional_fields:
            if hasattr(custom_attribute, f'x_misp_{field}'):
                attribute[field] = getattr(custom_attribute, f'x_misp_{field}')
        attribute.update(
            self.main_parser._sanitise_attribute_uuid(
                custom_attribute.id, comment=attribute.get('comment')
            )
        )
        self.main_parser._add_misp_attribute(attribute, custom_attribute)

    def _parse_custom_event_report(
            self, custom_event_report: _CUSTOM_OBJECT_TYPING):
        event_report = MISPEventReport()
        event_report.from_dict(
            content=custom_event_report.x_misp_content,
            name=custom_event_report.x_misp_name,
            timestamp=custom_event_report.modified,
            uuid=self.main_parser._sanitise_uuid(custom_event_report.id)
        )
        self.main_parser._add_event_report(event_report, custom_event_report.id)

    def _parse_custom_galaxy_cluster(
            self, custom_galaxy: _CUSTOM_OBJECT_TYPING):
        custom_ref = custom_galaxy.id
        clusters = self.main_parser._clusters
        if custom_ref in clusters:
            clusters[custom_ref]['used'][self.event_uuid] = False
        else:
            galaxy_type = custom_galaxy.x_misp_type
            cluster_args = {
                'type': galaxy_type, 'value': custom_galaxy.x_misp_value,
                'description': custom_galaxy.x_misp_description,
                'uuid': self.main_parser._sanitise_uuid(custom_galaxy.id)
            }
            if hasattr(custom_galaxy, 'x_misp_meta'):
                cluster_args['meta'] = custom_galaxy.x_misp_meta
            clusters[custom_ref] = {
                'used': {self.event_uuid: False},
                'cluster': self.main_parser._create_misp_galaxy_cluster(
                    **cluster_args
                )
            }
            if galaxy_type not in self.main_parser._galaxies:
                self._create_galaxy_args(galaxy_type, custom_galaxy.x_misp_name)

    def _parse_custom_object(self, custom_object: _CUSTOM_OBJECT_TYPING):
        name = custom_object.x_misp_name
        misp_object = self._create_misp_object(name)
        misp_object.category = custom_object.x_misp_meta_category
        misp_object.from_dict(**self._parse_timeline(custom_object))
        if hasattr(custom_object, 'x_misp_comment'):
            misp_object.comment = custom_object.x_misp_comment
        self.main_parser._sanitise_object_uuid(misp_object, custom_object.id)
        for custom_attribute in custom_object.x_misp_attributes:
            attribute = dict(custom_attribute)
            if attribute.get('uuid'):
                attribute.update(
                    self.main_parser._sanitise_attribute_uuid(
                        attribute['uuid'], attribute.get('comment')
                    )
                )
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, custom_object)

    @staticmethod
    def _sanitise_value(value: str) -> str:
        return value.replace('\\\\', '\\')
