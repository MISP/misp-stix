#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import InternalSTIX2Converter
from .stix2mapping import InternalSTIX2Mapping, STIX2Mapping
from pymisp import MISPEventReport
from stix2.v21 import Note
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser


class InternalSTIX2NoteMapping(InternalSTIX2Mapping):
    __annotation_object_mapping = Mapping(
        content=STIX2Mapping.text_attribute(),
        x_misp_attachment=InternalSTIX2Mapping.attachment_attribute(),
        x_misp_creation_date={
            'type': 'datetime', 'object_relation': 'creation-date'
        },
        x_misp_format=InternalSTIX2Mapping.format_attribute(),
        x_misp_modification_data={
            'type': 'datetime', 'object_relation': 'modification-date'
        },
        x_misp_ref={'type': 'link', 'object_relation': 'ref'},
        x_misp_type=STIX2Mapping.type_attribute()
    )

    @classmethod
    def annotation_object_mapping(cls) -> dict:
        return cls.__annotation_object_mapping


class InternalSTIX2NoteConverter(InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = InternalSTIX2NoteMapping

    def parse(self, note_ref: str):
        note = self.main_parser._get_stix_object(note_ref)
        labels = getattr(note, 'labels', [])
        if 'misp:data-layer="Event Report"' in labels:
            self._parse_event_report(note)
        elif 'misp:name="annotation"' in labels:
            self._parse_annotation_object(note)

    def _parse_annotation_object(self, note: Note):
        misp_object = self._create_misp_object('annotation', note)
        self.main_parser._sanitise_object_uuid(misp_object, note.id)
        misp_object.from_dict(**self._parse_timeline(note))
        for field, mapping in self._mapping.annotation_object_mapping().items():
            if hasattr(note, field):
                attributes = self._populate_object_attributes_with_data(
                    mapping, getattr(note, field), note.id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
        if hasattr(note, 'object_refs'):
            for object_ref in note.object_refs:
                misp_object.add_reference(
                    self.main_parser._sanitise_uuid(object_ref), 'annotates'
                )
        self.main_parser._add_misp_object(misp_object, note)

    def _parse_event_report(self, note: Note):
        event_report = MISPEventReport()
        event_report.from_dict(
            content=note.content, name=note.abstract, timestamp=note.modified,
            uuid=self.main_parser._sanitise_uuid(note.id)
        )
        self.main_parser._add_event_report(event_report, note.id)
