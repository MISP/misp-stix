#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ...misp_stix_mapping import Mapping
from ...tools.misp_object_templates import (
    _ORIGINAL_NAMES_PROPERTY, _rejected_name_note, _sanitise_template_name,
    _UNKNOWN_TEMPLATE_NAME)
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import InternalSTIX2Converter, _unreadable_misp_value
from .stix2mapping import InternalSTIX2Mapping
from collections import abc
from pymisp import MISPEventReport, MISPObject
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21
from typing import Any, Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_attribute_additional_fields = (
    'category', 'comment', 'data', 'to_ids', 'uuid'
)
# Mirrors what the export side writes into `x_misp_attributes` — anything else
# is not part of the round-trip contract and never comes from STIX content
_object_attribute_fields = (
    'type', 'object_relation', 'value', *_attribute_additional_fields
)
# The `misp-*` types carry what MISP writes under the names MISP gives it:
# besides the type and the value, a `misp-attribute` holds these, its uuid
# being the one of its id
_misp_attribute_fields = (
    'category', 'comment', 'to_ids', 'first_seen', 'last_seen', 'data'
)
# and the items of a `misp-object` hold their first and last seen times too
_misp_object_attribute_fields = (
    *_object_attribute_fields, 'first_seen', 'last_seen'
)
_CUSTOM_OBJECT_TYPING = Union[
    CustomObject_v20, CustomObject_v21
]
# The import registers no class for the `misp-*` types, so they reach it as
# plain dictionaries, unless another module registers one: they are read
# through the Mapping interface both forms offer
_MISP_OBJECT_TYPING = Union[CustomObject_v21, dict]


class STIX2CustomObjectMapping(InternalSTIX2Mapping):
    __custom_object_mapping = Mapping(
        **{
            'misp-attribute': '_parse_misp_attribute',
            'misp-galaxy-cluster': '_parse_misp_galaxy_cluster',
            'misp-object': '_parse_misp_object',
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
        feature = self._mapping.custom_object_mapping(custom_object['type'])
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
                f"{custom_object['id']}: {_traceback}"
            )

    def _parse_custom_attribute(self, custom_attribute: _CUSTOM_OBJECT_TYPING):
        attribute = {
            "type": custom_attribute.x_misp_type,
            "value": custom_attribute.x_misp_value
        }
        for field in _attribute_additional_fields:
            if hasattr(custom_attribute, f'x_misp_{field}'):
                attribute[field] = getattr(custom_attribute, f'x_misp_{field}')
        self._add_custom_attribute(attribute, custom_attribute)

    def _parse_misp_attribute(self, custom_attribute: _MISP_OBJECT_TYPING):
        attribute = {
            'type': custom_attribute['attribute_type'],
            'value': custom_attribute['value']
        }
        for field in _misp_attribute_fields:
            if field in custom_attribute:
                attribute[field] = custom_attribute[field]
        self._add_custom_attribute(attribute, custom_attribute)

    def _add_custom_attribute(
            self, attribute: dict,
            custom_attribute: _CUSTOM_OBJECT_TYPING | _MISP_OBJECT_TYPING):
        # In both syntaxes, the attribute takes its uuid from the id and its
        # timestamp from the modification time
        attribute['timestamp'] = self.main_parser._timestamp_from_stix_date(
            custom_attribute['modified']
        )
        attribute.update(
            self.main_parser._sanitise_attribute_uuid(
                custom_attribute['id'], comment=attribute.get('comment')
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
        if self._reuse_galaxy_cluster(custom_galaxy.id):
            return
        cluster_args = {
            'type': custom_galaxy.x_misp_type,
            'value': custom_galaxy.x_misp_value,
            'description': custom_galaxy.x_misp_description,
            'uuid': self.main_parser._sanitise_cluster_uuid(custom_galaxy.id)
        }
        if hasattr(custom_galaxy, 'x_misp_meta'):
            cluster_args['meta'] = self._restore_meta_dictionary(
                custom_galaxy, 'x_misp_meta', _ORIGINAL_NAMES_PROPERTY
            )
        self._add_custom_galaxy_cluster(
            custom_galaxy.id, cluster_args, custom_galaxy.x_misp_name
        )

    def _parse_misp_galaxy_cluster(self, custom_galaxy: _MISP_OBJECT_TYPING):
        # The cluster's description and its galaxy's come apart here, each
        # read as written, where the `x-misp-galaxy-cluster` joins them
        custom_ref = custom_galaxy['id']
        if self._reuse_galaxy_cluster(custom_ref):
            return
        cluster_args = {
            'type': custom_galaxy['galaxy_type'],
            'value': custom_galaxy['value'],
            'uuid': self.main_parser._sanitise_cluster_uuid(custom_ref)
        }
        if 'description' in custom_galaxy:
            cluster_args['description'] = custom_galaxy['description']
        # A channel that is no dictionary spells no meta key: it costs the
        # cluster, as an unreadable MISP Extension value does
        original_names = custom_galaxy.get('original_names', {})
        if not isinstance(original_names, abc.Mapping):
            _unreadable_misp_value('original_names', 'a dictionary')
        if 'meta' in custom_galaxy:
            cluster_args['meta'] = self._restore_meta_dictionary(
                custom_galaxy, 'meta', 'original_names'
            )
        self._add_custom_galaxy_cluster(
            custom_ref, cluster_args, custom_galaxy['galaxy_name'],
            custom_galaxy.get('galaxy_description')
        )

    def _reuse_galaxy_cluster(self, custom_ref: str) -> bool:
        # A cluster an earlier event of the bundle built is used by this
        # event too, and not built again
        clusters = self.main_parser._clusters
        if custom_ref not in clusters:
            return False
        clusters[custom_ref]['used'][self.event_uuid] = False
        return True

    def _add_custom_galaxy_cluster(
            self, custom_ref: str, cluster_args: dict, galaxy_name: str,
            galaxy_description: Optional[str] = None):
        self.main_parser._clusters[custom_ref] = {
            'used': {self.event_uuid: False},
            'cluster': self.main_parser._create_misp_galaxy_cluster(
                **cluster_args
            )
        }
        galaxy_type = cluster_args['type']
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(
                galaxy_type, galaxy_name, galaxy_description
            )

    def _parse_custom_object(self, custom_object: _CUSTOM_OBJECT_TYPING):
        # A name that is not a plain template name would be joined into a
        # filesystem path by pymisp's template resolution: keep it out of that
        # join and convert the object as a generic, template-less one.
        name, rejected_name = _sanitise_template_name(custom_object.x_misp_name)
        misp_object = self._create_misp_object(name)
        misp_object.category = custom_object.x_misp_meta_category
        misp_object.from_dict(**self._parse_timeline(custom_object))
        if hasattr(custom_object, 'x_misp_comment'):
            misp_object.comment = custom_object.x_misp_comment
        self._add_custom_object(
            misp_object, custom_object, rejected_name,
            custom_object.x_misp_attributes, _object_attribute_fields
        )

    def _parse_misp_object(self, custom_object: _MISP_OBJECT_TYPING):
        name, rejected_name = _sanitise_template_name(custom_object['name'])
        misp_object = self._create_misp_object(name)
        misp_object.category = custom_object['meta_category']
        misp_object.from_dict(
            **self._parse_timeline(custom_object),
            **{
                field: custom_object[field]
                for field in ('first_seen', 'last_seen')
                if field in custom_object
            }
        )
        if 'comment' in custom_object:
            misp_object.comment = custom_object['comment']
        self._add_custom_object(
            misp_object, custom_object, rejected_name,
            custom_object['attributes'], _misp_object_attribute_fields
        )

    def _add_custom_object(
            self, misp_object: MISPObject,
            custom_object: _CUSTOM_OBJECT_TYPING | _MISP_OBJECT_TYPING,
            rejected_name: Optional[Any], custom_attributes: list,
            attribute_fields: tuple):
        # In both syntaxes, the template name the object could not take is
        # kept as data, the object takes its uuid from the id, and each
        # attribute is read from the keys the syntax writes, the others
        # reported
        object_id = custom_object['id']
        if rejected_name is not None:
            self._record_rejected_template_name(misp_object, rejected_name)
            self.main_parser._add_warning(
                f'Invalid MISP object template name {rejected_name!r} in the '
                f'Custom object with id {object_id}: converted as a '
                f'{_UNKNOWN_TEMPLATE_NAME} object.'
            )
        self.main_parser._sanitise_object_uuid(misp_object, object_id)
        dropped_fields = set()
        for custom_attribute in custom_attributes:
            attribute = {
                field: custom_attribute[field]
                for field in attribute_fields if field in custom_attribute
            }
            dropped_fields.update(
                field for field in custom_attribute
                if field not in attribute_fields
            )
            if attribute.get('uuid'):
                attribute.update(
                    self.main_parser._sanitise_attribute_uuid(
                        attribute['uuid'], attribute.get('comment')
                    )
                )
            misp_object.add_attribute(**attribute)
        if dropped_fields:
            self.main_parser._add_warning(
                'Dropped attribute fields that are never imported from STIX '
                f'content, in the Custom object with id {object_id}: '
                f"{', '.join(sorted(dropped_fields))}"
            )
        self.main_parser._add_misp_object(misp_object, custom_object)

    def _restore_meta_dictionary(
            self, custom_galaxy: _CUSTOM_OBJECT_TYPING | _MISP_OBJECT_TYPING,
            meta_field: str, channel: str) -> dict:
        # The meta keys the export folded to the STIX dictionary charset come
        # back as MISP spelled them, from the channel - which keys on the
        # dictionary key here, not on a property name; the others were
        # written verbatim. Each syntax names the dictionary and the channel
        # its own way.
        meta = custom_galaxy[meta_field]
        original_names = self._read_original_names(
            custom_galaxy, meta, channel
        ) or {}
        return {
            original_names.get(key, key): value for key, value in meta.items()
        }

    @staticmethod
    def _record_rejected_template_name(misp_object: MISPObject, name: Any):
        # Nothing is silently dropped: the name the object cannot carry is
        # kept as data, in the comment, alongside whatever comment the STIX
        # content provided.
        note = _rejected_name_note(name)
        comment = getattr(misp_object, 'comment', None)
        misp_object.comment = f'{comment}\n{note}' if comment else note
