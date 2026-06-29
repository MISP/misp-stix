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
