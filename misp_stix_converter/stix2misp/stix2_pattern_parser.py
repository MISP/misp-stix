import ast
import stix2patterns.v20.object_validator as validator_v20
import stix2patterns.v21.object_validator as validator_v21
from antlr4 import CommonTokenStream, InputStream, ParseTreeWalker
from stix2.v20.sdo import Indicator as Indicator_v20
from stix2.v21.sdo import Indicator as Indicator_v21
from stix2patterns.exceptions import STIXPatternErrorListener
from stix2patterns.v20.grammars.STIXPatternLexer import STIXPatternLexer as lexer_v20
from stix2patterns.v20.grammars.STIXPatternParser import STIXPatternParser as parser_v20
from stix2patterns.v20.inspector import InspectionListener as inspector_v20
from stix2patterns.v21.grammars.STIXPatternLexer import STIXPatternLexer as lexer_v21
from stix2patterns.v21.grammars.STIXPatternParser import STIXPatternParser as parser_v21
from stix2patterns.v21.inspector import InspectionListener as inspector_v21
from typing import Union


class STIX2PatternParser:
    def __init__(self):
        self.__pattern_data: dict
        self.__valid: bool
        self.__valid_versions = ('2.0', '2.1')

    @property
    def errors(self):
        return self.__errors

    @property
    def pattern(self):
        return self.__pattern_data

    @property
    def valid(self) -> bool:
        return self.__valid

    @property
    def valid_versions(self) -> tuple:
        return self.__valid_versions

    def handle_indicator(
            self, indicator: Union[Indicator_v20, Indicator_v21, dict]):
        version = self.__set_version(indicator.get('spec_version', '2.0'))
        getattr(self, f'_load_stix_{version}_pattern')(indicator['pattern'])

    def _load_stix_20_pattern(self, pattern_str: str):
        pattern = InputStream(pattern_str)
        parseErrListener = STIXPatternErrorListener()
        lexer = lexer_v20(pattern)
        lexer.removeErrorListeners()
        stream = CommonTokenStream(lexer)
        parser = parser_v20(stream)
        parser.removeErrorListeners()
        parser.addErrorListener(parseErrListener)
        for i, lit_name in enumerate(parser.literalNames):
            if lit_name == u"<INVALID>":
                parser.literalNames[i] = parser.symbolicNames[i]
        tree = parser.pattern()
        inspection_listener = inspector_v20()
        if len(parseErrListener.err_strings) == 0:
            ParseTreeWalker.DEFAULT.walk(inspection_listener, tree)
            pattern_data = inspection_listener.pattern_data()
            obj_validator_results = validator_v20.verify_object(pattern_data)
            if obj_validator_results:
                parseErrListener.err_strings.extend(obj_validator_results)
            else:
                self.__set_pattern_data(pattern_data)
        self.__valid = self.__parse_err_listener(parseErrListener.err_strings)

    def _load_stix_21_pattern(self, pattern_str: str):
        pattern = InputStream(pattern_str)
        parseErrListener = STIXPatternErrorListener()
        lexer = lexer_v21(pattern)
        lexer.removeErrorListeners()
        stream = CommonTokenStream(lexer)
        parser = parser_v21(stream)
        parser.removeErrorListeners()
        parser.addErrorListener(parseErrListener)
        for i, lit_name in enumerate(parser.literalNames):
            if lit_name == u"<INVALID>":
                parser.literalNames[i] = parser.symbolicNames[i]
        tree = parser.pattern()
        inspection_listener = inspector_v21()
        if len(parseErrListener.err_strings) == 0:
            ParseTreeWalker.DEFAULT.walk(inspection_listener, tree)
            pattern_data = inspection_listener.pattern_data()
            obj_validator_results = validator_v21.verify_object(pattern_data)
            if obj_validator_results:
                parseErrListener.err_strings.extend(obj_validator_results)
            else:
                self.__set_pattern_data(pattern_data)
        self.__valid = self.__parse_err_listener(parseErrListener.err_strings)

    def __handle_value(
            self, features: list, assertion: str, value: str) -> list:
        return [
            [
                feature if isinstance(feature, str) else '[*]'
                for feature in features
            ],
            assertion, self.__validate_value(value)
        ]

    def __parse_err_listener(self, err_listener):
        if len(err_listener) == 0:
            return True
        self.__errors = err_listener
        return False

    def __set_pattern_data(self, pattern_data):
        for key, values in pattern_data.comparisons.items():
            pattern_data.comparisons[key] = [
                self.__handle_value(*value) for value in values
            ]
        self.__pattern_data = pattern_data

    def __set_version(self, version: str) -> str:
        if version in self.valid_versions:
            return version.replace('.', '')
        return '21'

    @staticmethod
    def __validate_value(value: str) -> Union[int, str, tuple]:
        try:
            return ast.literal_eval(value)
        except ValueError:
            return value
