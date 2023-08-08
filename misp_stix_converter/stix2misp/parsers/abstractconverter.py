# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from abc import ABCMeta
from uuid import UUID, uuid5

_RFC_VERSIONS = (1, 3, 4, 5)
_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')


class AbstractSTIXConverter(metaclass=ABCMeta):
    @staticmethod
    def _create_v5_uuid(value: str) -> UUID:
        return uuid5(_UUIDv4, value)

    def _sanitise_uuid(self, object_id: str) -> str:
        if UUID(object_uuid).version not in _RFC_VERSIONS:
            if object_uuid in self.main_parser.replacement_uuids:
                return self.main_parser.replacement_uuids[object_uuid]
            sanitised_uuid = self._create_v5_uuid(object_uuid)
            self.main_parser.replacement_uuids[object_uuid] = sanitised_uuid
            return sanitised_uuid
        return object_uuid
