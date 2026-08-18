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
