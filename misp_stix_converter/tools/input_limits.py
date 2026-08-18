# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from .exceptions import STIXInputSizeError
from pathlib import Path
from typing import Optional

# The documented default: a document larger than this is refused before it is
# parsed. Conversion costs 2 to 7 times the input size in memory - and, for
# STIX 2, about 4.4 seconds of CPU per megabyte - so the cap bounds what one
# document can make the converting host spend on it. Raisable per call, and
# `max_size=0` turns the limit off.
_MAX_INPUT_SIZE = 100 * 1024 * 1024

# How much of a string is encoded at a time to size it: enough that the count
# costs one pass, little enough that it never holds a second copy of the
# document it is sizing.
_SIZING_CHUNK_SIZE = 1024 * 1024


def _utf8_size(content: str) -> int:
    """The number of bytes a string holds - what the limit is expressed in -
    without encoding the whole of it at once: an ASCII document is its own
    length, and anything else is counted a chunk at a time."""
    if content.isascii():
        return len(content)
    return sum(
        len(content[index:index + _SIZING_CHUNK_SIZE].encode('utf-8'))
        for index in range(0, len(content), _SIZING_CHUNK_SIZE)
    )


def _check_input_size(size: int, max_size: Optional[int]) -> None:
    """`max_size` is the caller's limit in bytes, `None` the documented default
    and anything at or below 0 no limit at all."""
    limit = _MAX_INPUT_SIZE if max_size is None else max_size
    if limit <= 0 or size <= limit:
        return
    raise STIXInputSizeError(
        'The STIX content is larger than the maximum accepted input size '
        f'({limit} bytes) - raise the `max_size` argument to convert it anyway'
    )


def _check_input_file_size(filename, max_size: Optional[int]) -> None:
    """The size comes from the filesystem, so a document above the limit is
    refused without a byte of it being read. A file whose size cannot be read
    is left to the parser, which reports what makes it unreadable."""
    try:
        size = Path(filename).stat().st_size
    except (OSError, TypeError, ValueError):
        return
    _check_input_size(size, max_size)
