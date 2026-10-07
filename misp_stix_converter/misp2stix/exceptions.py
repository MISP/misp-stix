# -*- coding: utf-8 -*-
#!/usr/bin/env python3


class MISPtoSTIXError(Exception):
    def __init__(self, message):
        super(MISPtoSTIXError, self).__init__(message)
        self.message = message


class InvalidHashValueError(MISPtoSTIXError):
    pass


class InvalidMISPInputError(MISPtoSTIXError):
    pass


class _UnbuildableRecordError(Exception):
    """A record whose STIX object cannot be built once the values no native
    property holds went to custom properties: it goes out whole as the
    custom record, with the warnings those values already gave and no
    error."""
