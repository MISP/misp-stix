# -*- coding: utf-8 -*-
#!/usr/bin/env python3


class STIXtoMISPError(Exception):
    def __init__(self, message):
        super(STIXtoMISPError, self).__init__(message)
        self.message = message


class AttributeFromPatternParsingError(STIXtoMISPError):
    pass


class InvalidSTIXPatternError(STIXtoMISPError):
    pass


class MarkingDefinitionLoadingError(STIXtoMISPError):
    pass


class ObjectRefLoadingError(STIXtoMISPError):
    pass


class ObjectTypeLoadingError(STIXtoMISPError):
    pass


class SynonymsResourceJSONError(STIXtoMISPError):
    pass


class UnavailableGalaxyResourcesError(STIXtoMISPError):
    pass


class UnavailableSynonymsResourceError(STIXtoMISPError):
    pass


class UndefinedIndicatorError(STIXtoMISPError):
    pass


class UndefinedSTIXObjectError(STIXtoMISPError):
    pass


class UndefinedObservableError(STIXtoMISPError):
    pass


class UnknownAttributeTypeError(STIXtoMISPError):
    pass


class UnknownObjectNameError(STIXtoMISPError):
    pass


class UnknownObservableMappingError(STIXtoMISPError):
    pass


class UnknownParsingFunctionError(STIXtoMISPError):
    pass


class UnknownPatternMappingError(STIXtoMISPError):
    pass


class UnknownPatternTypeError(STIXtoMISPError):
    pass


class UnknownStixObjectTypeError(STIXtoMISPError):
    pass