# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from pathlib import PurePath


class STIXLoadingError(Exception):
    """Raised when a STIX document cannot be loaded, instead of terminating
    the calling process."""
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class STIXInputSizeError(STIXLoadingError):
    """Raised when an input document is larger than the accepted maximum,
    instead of parsing it to find out what it holds."""


def _reduce_input_path(message: str, filename) -> str:
    """Underlying parsing errors embed the resolved input path - keep the
    operator-facing text down to the file name."""
    filename = str(filename)
    return message.replace(filename, PurePath(filename).name)


def _reduce_input_error(filename, error: Exception) -> str:
    """The error text an entry function reports for an input it could not
    convert names that input twice: the file it was handed, which it resolved,
    and the message the failure came with, which may embed that resolved path
    again. Keep both down to the file name - a loading failure reaching a
    caller through `parse_stix_content` and the same failure reaching it
    through an entry function say the same thing, and so does an export
    failing on the MISP file it read."""
    return (
        f'{PurePath(str(filename)).name} - '
        f'{_reduce_input_path(str(error), filename)}'
    )
