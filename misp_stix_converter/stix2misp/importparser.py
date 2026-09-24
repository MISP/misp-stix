#!/usr/bin/env python3

import json
import re
import traceback
from ..abstract import AbstractParser
from abc import ABCMeta
from datetime import datetime
from pymisp import MISPEvent, MISPObject
from pymisp.abstract import resources_path
from typing import Any, Optional, Union
from uuid import UUID, uuid4

MISP_org_uuid = '55f6ea65-aa10-4c5a-bf01-4f84950d210f'

_DEFAULT_DISTRIBUTION = 0

_VALID_DISTRIBUTIONS = (0, 1, 2, 3, 4)
_RFC_VERSIONS = (1, 3, 4, 5)

# What a conversion writes text into a MISP taxonomy tag with. The grammar
# `<namespace>:<predicate>="<value>"` has no escaping of its own: a `"` closes
# the slot it appears in, and what follows is then read as further taxonomy
# entries of the tag - text a document chose for itself deciding what else the
# record is tagged with. The control characters cannot be written into the XML
# and CSV exports the tag reaches either. Both are taken out of every slot a
# document reaches, along with the whitespace around what is left - the rest is
# kept as it stands, inner spaces and the `:` and `=` a plain name may carry
# included. `_build_tag` is where they all go through.
_TAG_VALUE_METACHARACTERS = re.compile(r'["\x00-\x1f\x7f]')


def _load_json_file(path) -> dict:
    with open(path, 'rb') as f:
        return json.load(f)


class ExternalSTIXtoMISPParser(metaclass=ABCMeta):
    def _set_cluster_distribution(
            self, distribution: int, sharing_group_id: Union[int, None]):
        cl_dis = {'distribution': self._sanitise_distribution(distribution)}
        if distribution == 4:
            if sharing_group_id is not None:
                cl_dis['sharing_group_id'] = self._sanitise_sharing_group_id(
                    sharing_group_id
                )
            else:
                cl_dis['distribution'] = 0
                self._cluster_distribution_and_sharing_group_id_error()
        self.__cluster_distribution = cl_dis

    def _set_organisation_uuid(self, organisation_uuid: Union[str, None]):
        self.__organisation_uuid = organisation_uuid or MISP_org_uuid

    @property
    def cluster_distribution(self) -> dict:
        return self.__cluster_distribution

    @property
    def organisation_uuid(self) -> str:
        return self.__organisation_uuid


class STIXtoMISPParser(AbstractParser):
    def __init__(self):
        super().__init__()
        self.__distribution: int
        self.__galaxies_as_tags: bool
        self.__galaxy_feature: str
        self.__producer: Union[str, None]
        self.__relationship_types: dict
        self.__sharing_group_id: Union[int, None]
        self.__title: Union[str, None]

        self.__replacement_uuids: dict = {}

    def record_classification(self, detected: bool, overridden: bool = False):
        """Record how this parser came to be the one converting the document.

        The parser knows its own kind - the External parsers carry the
        `ExternalSTIXtoMISPParser` mixin - so the caller states only what
        content-based detection found and whether the choice was the
        operator's, a Classification Override. Not overridden and detected
        records that the Internal parser was selected from content; overridden
        and disagreeing with detection records both sides. Anything else
        records nothing. To be called once the document is loaded, so the
        Warning lands under its Recording Identifier - the entry functions do,
        and an in-memory consumer running the detection itself does the same.

        :param detected: whether detection classified the document as Internal
        :param overridden: whether the classification was the operator's choice
            rather than what detection found
        """
        if not overridden:
            if detected:
                self._classification_from_content_warning()
            return
        internal = not isinstance(self, ExternalSTIXtoMISPParser)
        if detected != internal:
            self._classification_overridden_warning(detected, internal)

    def _add_producer_tag(self, misp_event: MISPEvent, producer: Any):
        """Tag the event with the producer, as one taxonomy entry at most.

        Sanitised here rather than with the other parameters in
        `_set_parameters`: a `producer` parameter a tag value cannot be made of
        has to leave the event without a producer tag, never falling back to
        the provenance the bundle claims for itself.

        :param misp_event: the event being created
        :param producer: the producer name, from the `producer` parameter or
            from the Identity the bundle credits itself to - from any source
        """
        name = self._clean_tag_slot(producer)
        if not name:
            self._unusable_producer_warning(producer)
            return
        if name != str(producer):
            self._sanitised_producer_warning(producer, name)
        misp_event.add_tag(self._build_tag('misp-galaxy', 'producer', name))

    @staticmethod
    def _clean_tag_slot(slot: Any) -> str:
        """The text a slot of the tag grammar can carry, of what it was handed.

        The rule itself, held apart from the reaction to it: `_build_tag` drops
        the tag a slot nothing survives from, `_add_producer_tag` leaves the
        event untagged and `_build_cluster_tag` keys the tag on the cluster
        uuid instead - three answers to the one question this asks.

        :param slot: the text a document supplied for a slot of the grammar
        :return: what of it a slot can carry, empty when nothing can
        """
        return _TAG_VALUE_METACHARACTERS.sub('', str(slot)).strip()

    def _build_tag(
            self, namespace: str, predicate: str,
            value: Optional[str] = None) -> Optional[str]:
        """Write the MISP taxonomy tag a conversion tags a record with.

        The one place a tag is built out of text the converted document
        supplied. The taxonomy grammar is the library's own and has no escaping
        of its own: a `"` ends the slot it appears in and what follows is read
        as further taxonomy entries, so what a slot cannot carry is taken out
        of each of them - the predicate naming the entry as much as the value
        it carries, both being slots the document reaches.

        :param namespace: the taxonomy the tag belongs to
        :param predicate: the entry of that taxonomy the tag is
        :param value: the value that entry carries, for the tags that have one
        :return: the tag, or None when a slot nothing survives from leaves no
            tag to write
        """
        slots = (namespace, predicate) if value is None else (
            namespace, predicate, value
        )
        cleaned = []
        for slot in slots:
            text = self._clean_tag_slot(slot)
            if not text:
                self._unusable_tag_value_warning(slot)
                return None
            if text != str(slot):
                self._sanitised_tag_value_warning(slot, text)
            cleaned.append(text)
        if value is None:
            return '{}:{}'.format(*cleaned)
        return '{}:{}="{}"'.format(*cleaned)

    def _build_cluster_tag(
            self, cluster_type: str, value: str,
            uuid: str) -> Optional[str]:
        """Write the tag naming a Galaxy Cluster the conversion also creates.

        MISP attaches a cluster to a record by matching the tag against the
        cluster, so a tag cleaned while the cluster keeps the value it was sent
        would name no cluster at all. The value a tag cannot be made of is
        therefore not cleaned here but replaced by the cluster uuid, which any
        tag can carry - the cluster keeping the value the document supplied.

        :param cluster_type: the galaxy the cluster belongs to
        :param value: the value the cluster is named by
        :param uuid: the cluster uuid, the tag's fallback to name it with
        :return: the tag naming the cluster
        """
        cleaned = self._clean_tag_slot(value)
        if cleaned != str(value):
            self._cluster_tag_by_uuid_warning(value, uuid)
            value = uuid
        return self._build_tag('misp-galaxy', cluster_type, value)

    def _populate_misp_event(self):
        self.misp_events.append(self.misp_event)

    def _reset_bundle_state(self):
        self.__replacement_uuids = {}
        try:
            del self.__misp_events
        except AttributeError:
            pass

    def _sanitise_distribution(self, distribution: int) -> int:
        try:
            sanitised = int(distribution)
        except (TypeError, ValueError) as error:
            self._distribution_error(error)
            return 0
        if sanitised in _VALID_DISTRIBUTIONS:
            return sanitised
        self._distribution_value_error(sanitised)
        return 0

    def _sanitise_sharing_group_id(
            self, sharing_group_id: Union[int, None]) -> Union[int, None]:
        if sharing_group_id is None:
            return None
        try:
            return int(sharing_group_id)
        except (TypeError, ValueError) as error:
            self._sharing_group_id_error(error)
            return None

    def _set_misp_event(self, misp_event: MISPEvent):
        self.__misp_event = misp_event

    def _set_misp_events(self):
        self.__misp_events = []

    def _set_parameters(self, distribution: int = _DEFAULT_DISTRIBUTION,
                        sharing_group_id: Optional[int] = None,
                        force_contextual_data: Optional[bool] = False,
                        galaxies_as_tags: Optional[bool] = False,
                        single_event: Optional[bool] = False,
                        producer: Optional[str] = None,
                        title: Optional[str] = None):
        self.__distribution = self._sanitise_distribution(distribution)
        self.__sharing_group_id = self._sanitise_sharing_group_id(
            sharing_group_id
        )
        if self.sharing_group_id is None and self.distribution == 4:
            self.__distribution = 0
            self._distribution_and_sharing_group_id_error()
        self.__force_contextual_data = force_contextual_data
        self.__galaxies_as_tags = galaxies_as_tags
        self.__galaxy_feature = (
            'as_tag_names' if self.galaxies_as_tags else 'as_container'
        )
        self.__single_event = single_event
        self.__producer = producer
        self.__title = title

    def _set_single_event(self, single_event: bool):
        self.__single_event = single_event

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def distribution(self) -> int:
        return self.__distribution

    @property
    def event_title(self) -> Union[str, None]:
        return self.__title

    @property
    def force_contextual_data(self) -> bool:
        return self.__force_contextual_data

    @property
    def galaxies_as_tags(self) -> bool:
        return self.__galaxies_as_tags

    @property
    def galaxy_feature(self) -> str:
        return self.__galaxy_feature

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def misp_events(self) -> Union[list, MISPEvent]:
        return getattr(
            self, '_STIXtoMISPParser__misp_events', self.__misp_event
        )

    @property
    def producer(self) -> Union[str, None]:
        return self.__producer

    @property
    def relationship_types(self) -> dict:
        try:
            return self.__relationship_types
        except AttributeError:
            self.__get_relationship_types()
            return self.__relationship_types

    @property
    def replacement_uuids(self) -> dict:
        return self.__replacement_uuids

    @property
    def sharing_group_id(self) -> Union[int, None]:
        return self.__sharing_group_id

    @property
    def single_event(self) -> bool:
        return self.__single_event

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    def _classification_from_content_warning(self):
        self._add_warning(
            'The Internal parser was selected from the document content '
            'itself. Use the `classification` parameter to make this '
            'choice explicit.'
        )

    def _classification_overridden_warning(
            self, detected: bool, internal: bool):
        self._add_warning(
            'The STIX document content is detected as '
            f"{'internal' if detected else 'external'}, but is parsed as "
            f"{'internal' if internal else 'external'} as requested with "
            'the `classification` parameter.'
        )

    def _cluster_distribution_and_sharing_group_id_error(self):
        self._add_error(
            'Invalid Cluster Sharing Group ID - '
            'cannot be None when distribution is 4',
            'init'
        )

    def _distribution_and_sharing_group_id_error(self):
        self._add_error(
            'Invalid Sharing Group ID - cannot be None when distribution is 4',
            'init'
        )

    def _distribution_error(self, exception: Exception):
        self._add_error(
            f'Wrong distribution format: {exception}', 'init'
        )

    def _distribution_value_error(self, distribution: int):
        self._add_error(
            f'Invalid distribution value: {distribution}', 'init'
        )

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _sanitised_producer_warning(self, producer: Any, sanitised: str):
        self._add_warning(
            f'Sanitised producer name: {producer} - what a MISP taxonomy tag '
            'value cannot carry was taken out, the event is tagged as '
            f'produced by {sanitised}'
        )

    def _cluster_tag_by_uuid_warning(self, value: Any, uuid: str):
        self._add_warning(
            f'Sanitised galaxy cluster tag: {value} - the cluster value '
            'carries what a MISP taxonomy tag value cannot, the tag names the '
            f'cluster by its uuid {uuid} instead'
        )

    def _sanitised_tag_value_warning(self, value: Any, sanitised: str):
        self._add_warning(
            f'Sanitised tag value: {value} - what a MISP taxonomy tag value '
            f'cannot carry was taken out, the tag written carries {sanitised}'
        )

    def _unusable_tag_value_warning(self, value: Any):
        self._add_warning(
            f'Unusable tag value: {value} - nothing a MISP taxonomy tag value '
            'can be made of, no tag is written'
        )

    def _sharing_group_id_error(self, exception: Exception):
        self._add_error(
            f'Wrong sharing group id format: {exception}', 'init'
        )

    def _unusable_producer_warning(self, producer: Any):
        self._add_warning(
            f'Unusable producer name: {producer} - nothing a MISP taxonomy '
            'tag value can be made of, the event carries no producer tag'
        )

    ############################################################################
    #            MISP OBJECT RELATIONSHIPS MAPPING CREATION METHODS            #
    ############################################################################

    def __get_relationship_types(self):
        relationships_path = resources_path / 'misp-objects' / 'relationships'
        relationships = _load_json_file(relationships_path / 'definition.json')
        self.__relationship_types = {
            relationship['name']: relationship['opposite'] for relationship
            in relationships['values'] if 'opposite' in relationship
        }

    ############################################################################
    #                     UUID SANITATION HANDLING METHODS                     #
    ############################################################################

    def _check_uuid(self, object_id: str):
        self._read_uuid(object_id)

    def _read_uuid(self, object_id: Optional[str]) -> tuple[str, bool]:
        """Read the uuid a record takes off the id of the STIX object it is
        converted from - every uuid sanitation helper reads it here, so an
        object and an attribute read from the same id never diverge.

        The uuid is the trailing 36 characters of the id when they parse as
        one: every id MISP writes, whatever the prefix carries - a STIX 1
        `{Type}` naming a template with a hyphen in it included. A uuid of a
        version MISP refuses is replaced by one derived from it; an id ending
        with no uuid - a STIX 1 id is a QName, nothing makes its tail a uuid -
        by one derived from the whole id, prefix and type included, so an
        `idref` resolves to the uuid its target took and a re-import lands on
        the same records. An element carrying no id takes a random uuid:
        nothing can reference it.

        :param object_id: the id, None or empty when the element carries none
        :return: the key the id is known by in `replacement_uuids` - the uuid
            it ends with, the whole id when it ends with none - and whether
            the uuid the key names is replaced
        """
        if not object_id:
            return str(uuid4()), False
        record_uuid = object_id[-36:]
        if self._is_uuid(record_uuid):
            if UUID(record_uuid).version in _RFC_VERSIONS:
                return record_uuid, False
        else:
            record_uuid = object_id
        if record_uuid not in self.replacement_uuids:
            self.replacement_uuids[record_uuid] = self._create_v5_uuid(
                record_uuid
            )
        return record_uuid, True

    @classmethod
    def _replaced_uuid_comment(cls, key: str) -> str:
        noun = 'UUID' if cls._is_uuid(key) else 'id'
        return f'Original {noun} was: {key}'

    def _sanitise_attribute_uuid(
            self, object_id: Optional[str], comment: Optional[str] = None,
            **kwargs) -> dict:
        attribute_uuid, _ = self._read_uuid(object_id)
        if attribute_uuid in self.replacement_uuids:
            attribute_comment = self._replaced_uuid_comment(attribute_uuid)
            if comment is not None:
                attribute_comment = f'{comment} - {attribute_comment}'
            return {
                'uuid': self.replacement_uuids[attribute_uuid],
                'comment': attribute_comment, **kwargs
            }
        attribute = {'uuid': attribute_uuid, **kwargs}
        if comment is not None:
            attribute['comment'] = comment
        return attribute

    def _sanitise_object_uuid(
            self, misp_object: Union[MISPEvent, MISPObject],
            object_id: Optional[str]):
        object_uuid, _ = self._read_uuid(object_id)
        if object_uuid in self.replacement_uuids:
            comment = self._replaced_uuid_comment(object_uuid)
            misp_object.comment = (
                f'{misp_object.comment} - {comment}'
                if hasattr(misp_object, 'comment') else comment
            )
            object_uuid = self.replacement_uuids[object_uuid]
        misp_object.uuid = object_uuid

    def _sanitise_uuid(self, object_id: Optional[str]) -> str:
        object_uuid, replaced = self._read_uuid(object_id)
        if replaced:
            return self.replacement_uuids[object_uuid]
        return object_uuid

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _is_uuid(value: str) -> bool:
        # The canonical form only: `UUID()` also reads braces, a `urn:uuid:`
        # prefix and a hex string with its hyphens anywhere
        try:
            return str(UUID(value)) == value.lower()
        except ValueError:
            return False

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
