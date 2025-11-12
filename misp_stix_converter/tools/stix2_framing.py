#!/usr/bin/env python3

from uuid import UUID, uuid4
from typing import Optional

json_footer = ']}\n'


def stix20_framing(uuid: Optional[UUID | str] = None) -> tuple:
    header = '{"type": "bundle", "spec_version": "2.0", "id":'
    if uuid is None:
        uuid = uuid4()
    return f'{header} "bundle--{uuid}", "objects": [', ', ', json_footer


def stix21_framing(uuid: Optional[UUID | str] = None) -> tuple:
    header = '{"type": "bundle", "id":'
    if uuid is None:
        uuid = uuid4()
    return f'{header} "bundle--{uuid}", "objects": [', ', ', json_footer
