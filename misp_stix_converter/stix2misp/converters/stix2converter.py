#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ._galaxy_definitions import GALAXY_DEFINITIONS
from ..exceptions import InvalidMISPExtensionError, UndefinedSTIXObjectError
from ...tools.misp_object_templates import (
    _custom_property_name, _custom_property_name_from_extension,
    _custom_property_relation, _CUSTOM_PROPERTY_PREFIX,
    _EXTENSION_RESERVED_NAMES, _MISP_PROPERTY_EXTENSION_ID,
    _ORIGINAL_NAMES_PROPERTY, _template_custom_properties)
from abc import ABCMeta
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
from pymisp import AbstractMISP, MISPGalaxyCluster, MISPObject
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, CourseOfAction as CourseOfAction_v20,
    IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, ThreatActor as ThreatActor_v20,
    Tool as Tool_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, CourseOfAction as CourseOfAction_v21,
    IntrusionSet as IntrusionSet_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21, ThreatActor as ThreatActor_v21,
    Tool as Tool_v21, Vulnerability as Vulnerability_v21)
from typing import (
    Any, Iterable, Iterator, Optional, Tuple, TYPE_CHECKING, Union)

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path
_DATETIME_REGEX = '%Y-%m-%dT%H:%M:%S'

# `dict` is part of the incoming typings: a STIX 2.0 Bundle keeps the object
# types 2.0 does not know (Location, Malware Analysis) as plain dictionaries,
# so every helper here reads through the Mapping interface both forms offer.
_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    CourseOfAction_v20, CourseOfAction_v21,
    IntrusionSet_v20, IntrusionSet_v21,
    Malware_v20, Malware_v21,
    ThreatActor_v20, ThreatActor_v21,
    Tool_v20, Tool_v21,
    Vulnerability_v20, Vulnerability_v21, dict
]
_MAIN_PARSER_TYPING = Union[
    'ExternalSTIX2toMISPParser', 'InternalSTIX2toMISPParser'
]
_SDO_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Malware_v20, Malware_v21,
    ObservedData_v20, ObservedData_v21, dict
]


class _CustomSyntaxView(Mapping):
    """A standard STIX object as the custom property syntax spells its MISP
    values.

    The object's own properties come first, its MISP property extension
    values next, each under the custom property name it stands for. A part
    of the object whose values sit in a Nested Room - the PE extension, a
    section, a registry value - is presented the same way, where the object
    holds it.
    """

    def __init__(self, stix_object, values: dict, paths: dict,
                 original_names: Optional[dict] = None,
                 parts: Optional[dict] = None):
        self.__stix_object = stix_object
        self.__values = values
        self.__paths = paths
        self.__original_names = original_names or {}
        self.__parts = parts or {}

    def __contains__(self, key: object) -> bool:
        return key in self.__values or key in self.__stix_object

    def __getitem__(self, key: str) -> Any:
        if key in self.__values:
            return self.__values[key]
        if key in self.__parts:
            return self.__parts[key]
        return self.__stix_object[key]

    def __iter__(self) -> Iterator[str]:
        yield from self.__stix_object
        for key in self.__values:
            if key not in self.__stix_object:
                yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def in_extension(self, field: str) -> bool:
        """Tell whether a value comes from the MISP property extension.

        :param field: a property name, as the readers read it
        :return: whether the value is read from the extension, rather than
            from a property of the object
        """
        return field in self.__paths

    @property
    def original_names(self) -> dict:
        """The MISP spelling of the galaxy meta keys the MISP property
        extension carries under a changed name, read in meta mode.

        :return: the meta key per custom property name, for the extension
            values only
        """
        return self.__original_names

    def path(self, field: str) -> str:
        """Spell a property as the bundle does, for the messages naming it.

        :param field: a property name, as the readers read it
        :return: the path of a MISP property extension value, the name
            itself for a property of the object
        """
        return self.__paths.get(field, field)


def _as_custom_syntax(
        stix_object, main_parser: _MAIN_PARSER_TYPING,
        meta: bool = False) -> _CustomSyntaxView:
    """Present a standard STIX object's MISP values as the readers name them.

    The Internal import reads the MISP values of a standard object under
    their custom property names, the `x_misp_` properties of the custom
    property syntax. A STIX 2.1 bundle may carry them in the MISP property
    extension instead, which is recognised by its fixed id as a key of
    `extensions`, and by nothing else: neither the extension definition
    objects, nor `extension_type`, nor the STIX version are read. Each
    extension property name is translated into the custom property name it
    stands for, so every reader keeps its names. The names the extension body
    uses for itself are no MISP value.

    The values of a galaxy cluster are its meta keys, read in meta mode. A
    meta key is free-form: no rule strips its escape, and no name is a fixed
    MISP field with a type of its own. The extension's `original_names`
    lists every name the fold or the escape changed, so each name is read as
    written, under the custom property prefix, and the channel is translated
    to the same names. It spells the extension's own values only, as the
    custom property channel spells the custom properties: an entry naming
    no extension value is reported and left out.

    An object may carry both syntaxes, and each value is read. The export
    never writes a value in both, so when both give the same custom property
    name, the extension's value is read and the other one reported.

    Every value is checked as the view is built, before any reader runs: a
    value the readers cannot read costs the whole object, as a malformed
    custom property does, and nothing is salvaged from it.

    Only an object with an id carries the extension. A part of one - a PE
    extension, a section, a registry value - takes its MISP values from the
    Nested Room standing for it, in the object's extension: the view
    presents the part with them wherever the object holds it, so a reader
    reaching the part through the view reads them. Whatever the part's own
    `extensions` hold is no MISP value. A list room is keyed by the
    positions of its STIX list's items, so a key naming no item cannot say
    which item a value belongs to, and costs the object as an unreadable
    value does. A STIX 2.0 observable, which no producer writes the
    extension on, is presented with no MISP value.

    The object is read through the Mapping interface only, as a typed object
    and a Dict-Form Object both offer it. An object already presented is
    returned as it is, so what its values meet is reported once.

    :param stix_object: the standard STIX object whose MISP values are read
    :param main_parser: the parser reporting what the reading meets
    :param meta: whether the values are the meta keys of a galaxy cluster
    :return: the object, with its MISP property extension values next to its
        own properties
    :raise InvalidMISPExtensionError: the MISP property extension holds
        content the readers cannot read
    """
    if isinstance(stix_object, _CustomSyntaxView):
        return stix_object
    if 'id' not in stix_object:
        return _CustomSyntaxView(stix_object, {}, {})
    path = f"extensions.'{_MISP_PROPERTY_EXTENSION_ID}'"
    extension = stix_object.get('extensions', {}).get(
        _MISP_PROPERTY_EXTENSION_ID, {}
    )
    if not isinstance(extension, Mapping):
        _unreadable_misp_value(path, 'a dictionary')
    if not isinstance(extension.get('original_names', {}), Mapping):
        _unreadable_misp_value(f'{path}.original_names', 'a dictionary')
    values, paths = _extension_values(
        stix_object['id'], stix_object, extension, path, main_parser,
        meta=meta, fixed_names=not meta
    )
    parts = _nested_parts(stix_object, extension, path, main_parser)
    if not meta:
        return _CustomSyntaxView(stix_object, values, paths, parts=parts)
    return _CustomSyntaxView(
        stix_object, values, paths, _extension_original_names(
            stix_object['id'], extension.get('original_names', {}), values,
            f'{path}.original_names', main_parser
        ),
        parts
    )


def _extension_values(
        object_id: str, stix_part, body: Mapping, path: str,
        main_parser: _MAIN_PARSER_TYPING, meta: bool = False,
        fixed_names: bool = False) -> Tuple[dict, dict]:
    # The MISP values one body of the extension holds for a part of the
    # object, or the object itself, under the custom property names they
    # stand for: the names the extension uses for itself are none of them
    values, paths = {}, {}
    for name, value in body.items():
        if name in _EXTENSION_RESERVED_NAMES:
            continue
        field = (
            f'{_CUSTOM_PROPERTY_PREFIX}{name}' if meta
            else _custom_property_name_from_extension(name)
        )
        paths[field] = f'{path}.{name}'
        _check_misp_value(name, value, paths[field], fixed_names)
        if field in stix_part:
            main_parser._custom_syntax_collision_warning(
                object_id, field, paths[field]
            )
        values[field] = value
    return values, paths


def _nested_parts(stix_object, extension: Mapping, path: str,
                  main_parser: _MAIN_PARSER_TYPING) -> dict:
    # The parts of the object a Nested Room holds the values of, each
    # presented with them, under the property of the object holding it
    object_id = stix_object['id']
    parts = {}
    if 'windows_pebinary_ext' in extension:
        room_path = f'{path}.windows_pebinary_ext'
        room = extension['windows_pebinary_ext']
        pe_extension = stix_object.get('extensions', {}).get(
            'windows-pebinary-ext'
        )
        if pe_extension is None or not isinstance(room, Mapping):
            _unreadable_misp_value(
                room_path, "a dictionary standing for the object's "
                "windows-pebinary-ext extension"
            )
        pe_parts = {}
        if 'sections' in room:
            pe_parts['sections'] = _list_room_parts(
                object_id, pe_extension.get('sections', []),
                room['sections'], f'{room_path}.sections',
                "extensions.'windows-pebinary-ext'.sections", main_parser
            )
        parts['extensions'] = {
            **stix_object['extensions'],
            'windows-pebinary-ext': _part_view(
                object_id, pe_extension, room, room_path, main_parser,
                pe_parts
            )
        }
    if 'values' in extension:
        parts['values'] = _list_room_parts(
            object_id, stix_object.get('values', []), extension['values'],
            f'{path}.values', 'values', main_parser
        )
    return parts


def _list_room_parts(
        object_id: str, items: list, room: Any, path: str, items_path: str,
        main_parser: _MAIN_PARSER_TYPING) -> list:
    # Room key "n", the decimal position with no leading zero, holds the
    # MISP values of STIX item n, an item with no key holding none: a key
    # naming no item would put values on none, so the room is unreadable
    keys = [str(index) for index in range(len(items))]
    if not isinstance(room, Mapping) or not set(room).issubset(keys):
        _unreadable_misp_value(
            path,
            f'a dictionary keyed by the positions of the items of {items_path}'
        )
    parts = []
    for key, item in zip(keys, items):
        item_path = f"{path}.'{key}'"
        room_item = room.get(key, {})
        if not isinstance(room_item, Mapping):
            _unreadable_misp_value(item_path, 'a dictionary')
        parts.append(
            _part_view(object_id, item, room_item, item_path, main_parser)
        )
    return parts


def _part_view(
        object_id: str, part, room: Mapping, path: str,
        main_parser: _MAIN_PARSER_TYPING,
        parts: Optional[dict] = None) -> _CustomSyntaxView:
    # A part of the object, with the MISP values of the room standing for it
    return _CustomSyntaxView(
        part, *_extension_values(object_id, part, room, path, main_parser),
        parts=parts
    )


def _extension_original_names(
        object_id: str, original_names: Mapping, values: dict, path: str,
        main_parser: _MAIN_PARSER_TYPING) -> dict:
    # The extension's channel, under the names its meta keys are read with:
    # an entry naming none of them is reported as the bundle spells it
    known, unknown = {}, []
    for name, key in original_names.items():
        field = f'{_CUSTOM_PROPERTY_PREFIX}{name}'
        if field in values:
            known[field] = key
        else:
            unknown.append(name)
    if unknown:
        main_parser._unknown_original_names_warning(object_id, unknown, path)
    return known


def _check_misp_value(name: str, value: Any, path: str, fixed_names: bool):
    # The two fixed MISP fields with a type of their own, which only the top
    # level of a standard object's extension holds - no meta key and no
    # Nested Room value is one - then the values of every other name: an
    # item, or a list of items
    fixed_field = name if fixed_names else None
    if fixed_field == 'opinion':
        if not isinstance(value, int) or isinstance(value, bool):
            _unreadable_misp_value(path, 'an integer')
    elif fixed_field == 'author_ref':
        if not isinstance(value, str):
            _unreadable_misp_value(path, 'an identifier')
    elif not all(
            _is_misp_value_item(item)
            for item in (value if isinstance(value, list) else (value,))):
        _unreadable_misp_value(
            path, 'a string, a boolean, a value and its data, or a list of them'
        )


def _is_misp_value_item(item: Any) -> bool:
    if isinstance(item, (bool, str)):
        return True
    return (
        isinstance(item, Mapping) and set(item) == {'value', 'data'}
        and all(isinstance(item[key], str) for key in item)
    )


def _unreadable_misp_value(path: str, expected: str):
    raise InvalidMISPExtensionError(
        f'Unreadable MISP Extension content {path}: {expected} is expected.'
    )


class STIX2Converter(metaclass=ABCMeta):
    __network_assets = {'src': 'source', 'dst': 'destination'}

    @property
    def network_assets(self) -> dict:
        return self.__network_assets

    def _set_main_parser(self, main: _MAIN_PARSER_TYPING):
        self.__main_parser = main

    @property
    def event_uuid(self) -> str:
        return self.main_parser.misp_event.uuid

    @property
    def main_parser(self) -> _MAIN_PARSER_TYPING:
        return self.__main_parser

    ############################################################################
    #                  MISP DATA STRUCTURES CREATION METHODS.                  #
    ############################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = self._parse_timeline(stix_object)
        attribute.update(
            self.main_parser._sanitise_attribute_uuid(
                stix_object['id'], comment=stix_object.get('description')
            )
        )
        return attribute

    def _create_misp_object(
            self, name: str,
            stix_object: Optional[_SDO_TYPING] = None,
            object_id: Optional[str] = None) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        if stix_object is not None:
            if object_id is None:
                self.main_parser._sanitise_object_uuid(
                    misp_object, stix_object['id']
                )
            else:
                misp_object.uuid = self.main_parser._create_v5_uuid(object_id)
            misp_object.from_dict(**self._parse_timeline(stix_object))
        return misp_object

    ############################################################################
    #                     STIX OBJECTS CONVERSION METHODS.                     #
    ############################################################################

    def _generic_parser(
            self, stix_object, feature: Optional[str] = None,
            name: Optional[str] = None) -> Iterator[dict]:
        # `name` is the MISP object template the attributes are for, given
        # when it is not the `feature` spelt with `-`: only the Internal
        # converter reads it, to restore object relations from the template.
        if feature is None:
            feature = stix_object['type'].replace('-', '_')
        mapping = getattr(self._mapping, f'{feature}_object_mapping')
        for field, attribute in mapping().items():
            if field in stix_object:
                yield from self._populate_object_attributes(
                    attribute, stix_object[field], stix_object['id']
                )

    def _populate_object_attribute(
            self, value: str, mapping: dict, attribute: dict) -> dict:
        return {'value': value, **mapping, **attribute}

    def _populate_object_attribute_with_data(
            self, value: dict | str, mapping: dict, **attribute: dict) -> dict:
        if isinstance(value, dict):
            return {**value, **mapping, **attribute}
        return self._populate_object_attribute(value, mapping, attribute)

    def _populate_object_attributes(
            self, mapping: dict, values: Union[list, str],
            object_id: str) -> Iterator[dict]:
        if isinstance(values, list):
            for value in values:
                uuid = self.main_parser._create_v5_uuid(
                    f"{object_id} - {mapping['object_relation']} - {value}"
                )
                yield self._populate_object_attribute(
                    value, mapping, {'uuid': uuid}
                )
        else:
            uuid = self.main_parser._create_v5_uuid(
                f"{object_id} - {mapping['object_relation']} - {values}"
            )
            yield self._populate_object_attribute(
                values, mapping, {'uuid': uuid}
            )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _handle_kill_chain_phases(kill_chain_phases: list) -> list:
        kill_chains = []
        for kill_chain in kill_chain_phases:
            kill_chains.append(
                f"{kill_chain['kill_chain_name']}:{kill_chain['phase_name']}"
            )
        return kill_chains

    @staticmethod
    def _handle_labels(meta: dict, labels: list):
        meta_labels = [
            label for label in labels if not label.startswith('misp:galaxy-')
        ]
        if meta_labels:
            meta['labels'] = meta_labels

    @staticmethod
    def _handle_misp_object_references(
            misp_object: MISPObject, *object_ids: tuple,
            relationship_type: str = 'contains'):
        for object_id in object_ids:
            if not any(reference.referenced_uuid == object_id and
                   reference.relationship_type == relationship_type
                   for reference in misp_object.references):
                misp_object.add_reference(object_id, relationship_type)

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

    def _parse_timeline(self, stix_object: _SDO_TYPING) -> dict:
        # A dict-form object keeps the timestamp string the document carried,
        # and the MISP side only takes a `datetime`
        misp_object = {
            'timestamp': self.main_parser._stix_date(stix_object['modified'])
        }
        object_type = stix_object['type']
        if self._mapping.timeline_mapping(object_type) is not None:
            first, last = self._mapping.timeline_mapping(object_type)
            if not self._skip_first_seen_last_seen(stix_object):
                if stix_object.get(first):
                    misp_object['first_seen'] = stix_object[first]
                if stix_object.get(last):
                    misp_object['last_seen'] = stix_object[last]
        return misp_object

    @staticmethod
    def _skip_first_seen_last_seen(sdo: _SDO_TYPING) -> bool:
        modified = sdo['modified']
        if sdo['type'] != 'indicator':
            return modified == sdo['first_observed'] == sdo['last_observed']
        if sdo['valid_from'] != modified:
            return False
        if 'valid_until' not in sdo:
            return True
        return sdo['valid_until'] == modified

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        # I keep it just in case
        # try:
        #     return int(date.timestamp())
        # except AttributeError:
        #     return int(
        #         time.mktime(
        #             time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")
        #         )
        #     )


class ExternalSTIX2Converter(STIX2Converter, metaclass=ABCMeta):

    def parse(self, stix_object_ref: str):
        stix_object = self.main_parser._get_stix_object(stix_object_ref)
        self._parse_galaxy(stix_object)

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        object_id = stix_object['id']
        value = cluster_value or stix_object.get('name', object_id)
        cluster_uuid = self.main_parser._create_v5_uuid(
            f'{self.main_parser._extract_uuid(object_id)} -'
            f' {self.main_parser.organisation_uuid}'
        )
        self.main_parser._check_record_uuid_collision(
            'galaxy cluster', cluster_uuid, object_id
        )
        cluster_args = {
            'value': value, **self.main_parser.cluster_distribution,
            'uuid': cluster_uuid,
            'source': (
                self.main_parser._handle_creator(stix_object['created_by_ref'])
                if 'created_by_ref' in stix_object else 'misp-stix'
            )
        }
        if galaxy_type is None:
            version = stix_object.get('spec_version', '2.0')
            mapping = self._mapping.galaxy_name_mapping(stix_object['type'])
            name = f"STIX {version} {mapping['name']}"
            cluster_args.update(
                {
                    'version': ''.join(version.split('.')),
                    'collection_uuid': self.main_parser._create_v5_uuid(name)
                }
            )
            galaxy_type = f"stix-{version}-{stix_object['type']}"
        cluster_args['type'] = galaxy_type
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if 'description' in stix_object:
            cluster_args['description'] = stix_object['description']
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                            galaxy_type: Optional[str] = None):
        if galaxy_type is None:
            galaxy_type = stix_object['type']
        mapping = self._mapping.galaxy_name_mapping(galaxy_type)
        name = mapping['name']
        galaxy_args = {
            'description': mapping['description'], 'namespace': 'stix',
            **self.main_parser.cluster_distribution
        }
        if galaxy_type not in ('country', 'region', 'sector'):
            version = stix_object.get('spec_version', '2.0')
            name = f"STIX {version} {name}"
            galaxy_args.update(
                {
                    'uuid': self.main_parser._create_v5_uuid(name),
                    'version': ''.join(version.split('.')),
                    'icon': mapping['icon']
                }
            )
            galaxy_type = f'stix-{version}-{galaxy_type}'
        galaxy_args.update({'type': galaxy_type, 'name': name})
        self.main_parser._galaxies[galaxy_type] = galaxy_args

    def _handle_datetime_meta_fields(
            self, stix_object: _GALAXY_OBJECTS_TYPING):
        for field in ('created', 'modified', 'first_seen', 'last_seen'):
            if stix_object.get(field) is not None:
                dt_value = self.main_parser._stix_date(stix_object[field])
                yield field, dt_value.strftime(
                    f'{_DATETIME_REGEX}.%fZ' if dt_value.microsecond != 0
                    else f'{_DATETIME_REGEX}Z'
                )

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object['type'].replace('-', '_')}_meta_mapping"
        meta = dict(self._handle_datetime_meta_fields(stix_object))
        if hasattr(self._mapping, mapping):
            for feature, field in getattr(self._mapping, mapping)().items():
                if feature in stix_object:
                    meta[field] = stix_object[feature]
        return meta

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING,
                      object_type: Optional[str] = None):
        clusters = self.main_parser._clusters
        object_id = stix_object['id']
        if object_id in clusters:
            clusters[object_id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[object_id] = getattr(self, feature)(
                stix_object, object_type
            )

    def _parse_galaxy_as_container(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        galaxy_type = object_type or stix_object['type']
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(stix_object, galaxy_type)
        galaxy_cluster = self._create_cluster(
            stix_object, galaxy_type=object_type
        )
        if 'object_marking_refs' in stix_object:
            for marking_ref in stix_object['object_marking_refs']:
                if marking_ref not in self.main_parser._clusters:
                    continue
                cluster = self.main_parser._clusters[marking_ref]
                if cluster['used'].get(self.event_uuid) is None:
                    cluster['used'][self.event_uuid] = False
                for misp_cluster in cluster['cluster']:
                    galaxy_cluster.add_cluster_relation(
                        misp_cluster.uuid, 'marked-with'
                    )
        return {
            'cluster': galaxy_cluster,
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        tag_name = self.main_parser._build_tag(
            'misp-galaxy', object_type or stix_object['type'],
            stix_object.get('name', stix_object['id'])
        )
        return {
            'tag_names': [tag_name] if tag_name is not None else [],
            'used': {self.event_uuid: False}
        }

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            if reference.get('external_id'):
                meta['external_id'].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta


class InternalSTIX2Converter(STIX2Converter, metaclass=ABCMeta):

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = super()._create_attribute_dict(stix_object)
        for field, value in self._parse_labels(stix_object).items():
            if field.startswith('misp:'):
                attribute[field.split(':')[-1]] = value
        return attribute

    ############################################################################
    #                   OBJECT RELATIONS RESTORATION METHODS.                   #
    ############################################################################

    def _generic_parser(
            self, stix_object, feature: Optional[str] = None,
            name: Optional[str] = None) -> Iterator[dict]:
        # The walk the base converter does, with every custom property
        # resolved against the object template first, and the ones the static
        # table does not list read after them instead of being dropped.
        stix_object = _as_custom_syntax(stix_object, self.main_parser)
        if feature is None:
            feature = stix_object['type'].replace('-', '_')
        if name is None:
            name = feature.replace('_', '-')
        mapping = getattr(self._mapping, f'{feature}_object_mapping')()
        object_id = stix_object['id']
        for field, attribute in mapping.items():
            if field in stix_object:
                yield from self._populate_object_attributes_with_data(
                    self._object_relation_mapping(
                        name, field, attribute, object_id
                    ),
                    stix_object[field], object_id
                )
        for field in self._unlisted_custom_properties(stix_object, mapping):
            yield from self._populate_object_attributes_with_data(
                self._object_relation_mapping(
                    name, field, None, object_id,
                    path=stix_object.path(field)
                ),
                stix_object[field], object_id
            )

    def _populate_object_attributes_with_data(
            self, mapping: dict, values: Any, object_id: str) -> Iterator[dict]:
        # A custom property carrying an attachment is a `value` and `data`
        # dictionary: the uuid is seeded on the value, as for any attribute
        for value in (values if isinstance(values, list) else (values,)):
            reference = value['value'] if isinstance(value, dict) else value
            yield self._populate_object_attribute_with_data(
                value, mapping, uuid=self.main_parser._create_v5_uuid(
                    f"{object_id} - {mapping['object_relation']} - {reference}"
                )
            )

    def _object_relation_mapping(
            self, name: str, field: str, mapping: Optional[dict],
            object_id: str, path: Optional[str] = None) -> Optional[dict]:
        """Pick the MISP attribute a property of an object's STIX form maps to.

        A custom property carries a MISP object relation folded to the STIX
        charset. The object template is the exact inverse of that fold, so it
        is asked first for the original spelling and the type; the static
        mapping table comes next, for what the template cannot say - a relation
        it has dropped since; failing both, the value survives as a text
        attribute under the folded relation and the loss of spelling and type
        is reported. Any other property maps through the static table alone.

        :param name: the MISP object template name
        :param field: the STIX property, or pattern segment, being read
        :param mapping: the static table entry for that property, if any
        :param object_id: the STIX object the property comes from
        :param path: the property as the bundle spells it, when it is not
            `field` - a MISP property extension value - for the warning
        :return: the `type` and `object_relation` the attribute takes
        """
        if not field.startswith(_CUSTOM_PROPERTY_PREFIX):
            return mapping
        # Re-folding the name reads the spellings exported before the fold
        # (`x_misp_KnownMalicious`) through the template as well
        folded = _custom_property_name(_custom_property_relation(field))
        attribute = _template_custom_properties(name).get(folded)
        if attribute is not None:
            return attribute
        if mapping is not None:
            return mapping
        relation = _custom_property_relation(folded)
        self.main_parser._unknown_custom_property_warning(
            name, object_id, path or field, relation
        )
        return {'type': 'text', 'object_relation': relation}

    @staticmethod
    def _unlisted_custom_properties(
            stix_object, mapping: dict) -> Iterator[str]:
        """Walk the custom properties a static mapping table does not list.

        :param stix_object: the STIX object being read, with its MISP property
            extension values under their custom property names
        :param mapping: the static table the reader iterates
        :return: the `x_misp_` properties the table would skip
        """
        for field in stix_object:
            if field.startswith(_CUSTOM_PROPERTY_PREFIX) and field not in mapping:
                yield field

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        object_id = stix_object['id']
        value = cluster_value or stix_object.get('name', object_id)
        cluster_args = {
            'uuid': self.main_parser._sanitise_cluster_uuid(object_id),
            'value': value, 'type': galaxy_type
        }
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if 'description' in stix_object:
            cluster_args['description'] = stix_object['description']
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, galaxy_type: str, galaxy_name: str,
                            galaxy_description: Optional[str] = None):
        # A galaxy MISP ships is read from its definition, any other from
        # what the bundle says of it
        if galaxy_type in GALAXY_DEFINITIONS:
            galaxy_args = GALAXY_DEFINITIONS[galaxy_type]
        else:
            galaxy_args = {'type': galaxy_type, 'name': galaxy_name}
            if galaxy_description is not None:
                galaxy_args['description'] = galaxy_description
        self.main_parser._galaxies[galaxy_type] = galaxy_args

    def _extract_custom_fields(self, stix_object: _GALAXY_OBJECTS_TYPING):
        # Each syntax's channel spells the meta keys of its own syntax. The
        # MISP property extension came with the channel, so a name it does
        # not list is verbatim, with no list to fall back on.
        original_names = self._read_original_names(stix_object)
        stix_object = _as_custom_syntax(
            stix_object, self.main_parser, meta=True
        )
        for key, value in stix_object.items():
            if key == _ORIGINAL_NAMES_PROPERTY:
                continue
            if stix_object.in_extension(key):
                yield stix_object.original_names.get(
                    key, _custom_property_relation(key)
                ), value
            elif key.startswith(_CUSTOM_PROPERTY_PREFIX):
                yield self._restore_meta_key(key, original_names), value

    @staticmethod
    def _handle_cluster_value(cluster_args: dict, external_id: str):
        cluster_value = cluster_args['value']
        if external_id not in cluster_value:
            cluster_args['value'] = f'{cluster_value} - {external_id}'

    @staticmethod
    def _handle_cluster_value_with_synonyms(cluster_args: dict, meta: dict):
        cluster_value = cluster_args['value']
        external_id = meta['external_id']
        if external_id not in cluster_value:
            cluster_args['value'] = f'{cluster_value} - {external_id}'
            if meta.get('synonyms') is None:
                meta['synonyms'] = [cluster_value]
            elif cluster_value not in meta['synonyms']:
                meta['synonyms'].append(cluster_value)

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object['type'].replace('-', '_')}_meta_mapping"
        if hasattr(self._mapping, mapping):
            meta = {}
            for feature, field in getattr(self._mapping, mapping)().items():
                if feature in stix_object:
                    meta[field] = stix_object[feature]
            meta.update(dict(self._extract_custom_fields(stix_object)))
            return meta
        return dict(self._extract_custom_fields(stix_object))

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING):
        clusters = self.main_parser._clusters
        object_id = stix_object['id']
        if object_id in clusters:
            clusters[object_id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[object_id] = getattr(self, feature)(stix_object)

    def _read_original_names(
            self, stix_object, names: Optional[Iterable[str]] = None,
            channel: str = _ORIGINAL_NAMES_PROPERTY) -> Optional[dict]:
        """Read the spellings the export carried for the names it folded.

        :param stix_object: the STIX object carrying the channel, if any
        :param names: the names the object writes, as the channel keys them -
            its own properties by default, or the keys of its meta dictionary
            when the channel spells those instead
        :param channel: the property carrying the channel -
            `original_names` on a `misp-galaxy-cluster`
        :return: the MISP spelling per wire name, or `None` when the object
            carries no channel - it is then older than the channel, or the
            fold changed none of its names
        """
        original_names = stix_object.get(channel)
        if original_names is None:
            return None
        if names is None:
            names = stix_object
        unknown = [name for name in original_names if name not in names]
        if unknown:
            self.main_parser._unknown_original_names_warning(
                stix_object['id'], unknown, channel
            )
        return original_names

    def _restore_meta_key(
            self, field: str, original_names: Optional[dict]) -> str:
        """Spell a leftover galaxy meta key as MISP had it.

        The channel is the exact inverse of the fold: on an object carrying
        it, a name it lists comes back as listed and any other was written
        verbatim. Without a channel, `dash_meta_fields` restores the `-` the
        names it lists lost in the bundles exported before the channel
        existed; the list is frozen there.

        :param field: the custom property carrying the meta key
        :param original_names: the channel, or `None` when the object has none
        :return: the meta key
        """
        relation = _custom_property_relation(field)
        if original_names is not None:
            return original_names.get(field, relation)
        if field in self._mapping.dash_meta_fields():
            return relation.replace('_', '-')
        return relation

    def _parse_galaxy_as_container(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, galaxy_name = self._extract_galaxy_labels(stix_object)
        cluster = self._parse_galaxy_cluster(stix_object, galaxy_type)
        if galaxy_name is None:
            self.main_parser._add_warning(
                'Missing MISP galaxy name label on the object with id '
                f"{stix_object['id']}"
            )
            galaxy_name = galaxy_type
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(galaxy_type, galaxy_name)
        return {
            'cluster': cluster,
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, _ = self._extract_galaxy_labels(stix_object)
        tag_name = self.main_parser._build_tag(
            'misp-galaxy', galaxy_type,
            stix_object.get('name', stix_object['id'])
        )
        return {
            'tag_names': [tag_name] if tag_name is not None else [],
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_cluster(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None) -> Tuple[MISPGalaxyCluster, str]:
        if stix_object.get('description', '').count(' | ') == 1:
            _, description = stix_object['description'].split(' | ')
        return self._create_cluster(
            stix_object, description=description, galaxy_type=galaxy_type
        )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    def _extract_galaxy_labels(
            self, stix_object: _GALAXY_OBJECTS_TYPING
            ) -> Tuple[str, Optional[str]]:
        labels = self._parse_labels(stix_object)
        galaxy_type = labels.get('misp:galaxy-type')
        if not galaxy_type:
            raise UndefinedSTIXObjectError(stix_object['id'])
        return galaxy_type, labels.get('misp:galaxy-name') or None

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            feature = (
                'aliases' if reference.get('source_name') == 'cve'
                else 'external_id'
            )
            if reference.get('external_id'):
                meta[feature].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _handle_mapping_from_labels(self, stix_object: _SDO_TYPING) -> str:
        parsed_labels = self._parse_labels(stix_object)
        if 'misp:galaxy-type' in parsed_labels:
            return '_parse_galaxy'
        if 'misp:name' in parsed_labels:
            to_call = self._mapping.objects_mapping(parsed_labels['misp:name'])
            if to_call is not None:
                return to_call
        elif 'misp:type' in parsed_labels:
            to_call = self._mapping.attributes_mapping(
                parsed_labels['misp:type']
            )
            if to_call is not None:
                return to_call
        raise UndefinedSTIXObjectError(stix_object['id'])

    @staticmethod
    def _parse_labels(stix_object: _SDO_TYPING) -> dict:
        """Index the `field=value` labels the Internal path dispatches on.

        Labels are content: an object may carry none, and any of them may be
        missing the `=` the field/value split needs. They are read through the
        Mapping interface a typed object and a Dict-Form Object both offer,
        never with attribute access: this is what every per-type converter
        dispatches on, and a dispatch reading no field takes no branch and
        drops the object saying nothing.
        """
        parsed_labels = {}
        for label in stix_object.get('labels', ()):
            field, separator, value = label.partition('=')
            if separator:
                parsed_labels[field] = value.strip('"')
        return parsed_labels
