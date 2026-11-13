#!/usr/bin/env python3

from abc import ABCMeta
from collections import Counter, defaultdict
from typing import Optional
from uuid import UUID, uuid5

_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')

# How many distinct messages `diagnostics` keeps per Recording Identifier in
# each bucket - a single document can produce a message per object it carries
_DIAGNOSTICS_LIMIT = 10


class AbstractParser(metaclass=ABCMeta):

    def __init__(self):
        self.__errors: defaultdict = defaultdict(list)
        # A dict keyed by message rather than a set: the same distinctness, in
        # the order the warnings were recorded - so the Diagnostics read the
        # same across runs and a cap keeps the first ones
        self.__warnings: defaultdict = defaultdict(dict)
        self.__identifier: str = 'misp event'

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def identifier(self) -> str:
        return self.__identifier

    @property
    def warnings(self) -> dict:
        return {
            identifier: list(warnings)
            for identifier, warnings in self.__warnings.items()
        }

    def diagnostics(self) -> dict:
        """What the parser recorded, summarised for a reader.

        `warnings` and `errors` hold the distinct messages recorded under each
        Recording Identifier - errors with the number of times each happened -
        capped at `_DIAGNOSTICS_LIMIT` per identifier, the first recorded, with
        a trailing entry naming the remainder. `counts` are taken before the
        cap and summed over identifiers: distinct warnings, error occurrences.
        Fresh dicts, aliasing nothing the parser goes on recording into.
        """
        return {
            'warnings': {
                identifier: _cap_messages(list(warnings), 'warning')
                for identifier, warnings in self.__warnings.items()
                if warnings
            },
            'errors': {
                identifier: _cap_messages(_count_occurrences(errors), 'error')
                for identifier, errors in self.__errors.items() if errors
            },
            'counts': {
                'warnings': sum(
                    len(warnings) for warnings in self.__warnings.values()
                ),
                'errors': sum(len(errors) for errors in self.__errors.values())
            }
        }

    @staticmethod
    def _create_v5_uuid(value: str) -> UUID:
        return uuid5(_UUIDv4, value)

    def _set_identifier(self, identifier: str):
        self.__identifier = identifier

    def _add_error(self, error: str, identifier: Optional[str] = None):
        self.__errors[identifier or self.identifier].append(error)

    def _add_warning(self, warning: str, identifier: Optional[str] = None):
        self.__warnings[identifier or self.identifier][warning] = None


def _cap_messages(messages: list, kind: str) -> list:
    remaining = len(messages) - _DIAGNOSTICS_LIMIT
    if remaining <= 0:
        return messages
    return messages[:_DIAGNOSTICS_LIMIT] + [
        f"... and {remaining} more {kind}{'s' if remaining > 1 else ''}"
    ]


def _count_occurrences(messages: list) -> list:
    # Messages carrying no object id are indistinguishable, so how many times
    # each happened is part of the signal: hundreds of objects dropped the
    # same way must not read like one
    return [
        message if occurrences == 1 else f'{message} ({occurrences} times)'
        for message, occurrences in Counter(messages).items()
    ]
