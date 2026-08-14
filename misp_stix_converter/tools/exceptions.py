# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from pathlib import PurePath


class STIXLoadingError(Exception):
    """Raised when a STIX document cannot be loaded, instead of terminating
    the calling process."""
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def _reduce_input_path(message: str, filename) -> str:
    """Underlying parsing errors embed the resolved input path - keep the
    operator-facing text down to the file name."""
    filename = str(filename)
    return message.replace(filename, PurePath(filename).name)
