#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import STIX2Converter
from .stix2mapping import InternalSTIX2Mapping, STIX2Mapping
from abc import ABCMeta
from pymisp import AbstractMISP, MISPObject
from stix2.v21.observables import Artifact, File, Software
from stix2.v21.sdo import Malware
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from .stix2_malware_converter import (
        ExternalSTIX2MalwareConverter, InternalSTIX2MalwareConverter)

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

_MAIN_CONVERTER_TYPING = Union[
    'ExternalSTIX2MalwareConverter', 'InternalSTIX2MalwareConverter'
]
_OBSERVABLE_TYPING = Union[
    Artifact, File, Software
]


class STIX2ObservableMapping(metaclass=ABCMeta):
    __artifact_object_mapping = Mapping(
        decryption_key={'type': '', 'object_relation': 'decryption_key'},
        encyption_algorithm={
            'type': '', 'object_relation': 'encryption_algorithm'
        },
        mime_type={'type': 'mime-type', 'object_relation': 'mime_type'},
        payload_bin={'type': 'text', 'object_relation': 'payload_bin'},
        url=STIX2Mapping.url_attribute()
    )
    __software_object_mapping = Mapping(
        cpe={'type': 'cpe', 'object_relation': 'cpe'},
        languages={'type': 'text', 'object_relation': 'language'},
        name={'type': 'text', 'object_relation': 'name'},
        swid={'type': 'text', 'object_relation': 'swid'},
        vendor={'type': 'text', 'object_relation': 'vendor'},
        version={'type': 'text', 'object_relation': 'version'}
    )

    @classmethod
    def artifact_object_mapping(cls) -> dict:
        return cls.__artifact_object_mapping

    @classmethod
    def software_object_mapping(cls) -> dict:
        return cls.__software_object_mapping


class ExternalSTIX2ObservableMapping(STIX2ObservableMapping):
    __file_hashes_mapping = Mapping(
        **{
            'MD5': STIX2Mapping.md5_attribute(),
            'SHA-1': STIX2Mapping.sha1_attribute(),
            'SHA-256': STIX2Mapping.sha256_attribute(),
            'SHA-512': STIX2Mapping.sha512_attribute(),
            'SHA3-256': STIX2Mapping.sha3_256_attribute(),
            'SHA3-512': STIX2Mapping.sha3_512_attribute(),
            'SSDEEP': STIX2Mapping.ssdeep_attribute(),
            'TLSH': STIX2Mapping.tlsh_attribute()
        }
    )
    __file_object_mapping = Mapping(
        accessed=STIX2Mapping.access_time_attribute(),
        atime=STIX2Mapping.access_time_attribute(),
        created=STIX2Mapping.creation_time_attribute(),
        ctime=STIX2Mapping.creation_time_attribute(),
        mime_type=STIX2Mapping.mime_type_attribute(),
        modified=STIX2Mapping.modification_time_attribute(),
        mtime=STIX2Mapping.modification_time_attribute(),
        name=STIX2Mapping.filename_attribute(),
        name_enc=STIX2Mapping.file_encoding_attribute(),
        size=STIX2Mapping.size_in_bytes_attribute()
    )

    @classmethod
    def file_hashes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__file_hashes_mapping.get(field)

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping


class InternalSTIX2ObservableMapping(STIX2ObservableMapping):
    # SINGLE ATTRIBUTES
    __authentihash_attribute = {
        'type': 'authentihash', 'object_relation': 'authentihash'
    }
    __sha224_attribute = {'type': 'sha224', 'object_relation': 'sha224'}
    __sha3_224_attribute = {'type': 'sha3-224', 'object_relation': 'sha3-224'}
    __sha3_384_attribute = {'type': 'sha3-384', 'object_relation': 'sha3-384'}
    __sha384_attribute = {'type': 'sha384', 'object_relation': 'sha384'}
    __telfhash_attribute = {'type': 'telfhash', 'object_relation': 'telfhash'}
    __vhash_attribute = {'type': 'vhash', 'object_relation': 'vhash'}
    __certificate_attribute = {
        'type': 'x509-fingerprint-sha1', 'object_relation': 'certificate'
    }
    __compilation_timestamp_attribute = {
        'type': 'datetime', 'object_relation': 'compilation-timestamp'
    }
    __fullpath_attribute = {'type': 'text', 'object_relation': 'fullpath'}
    __pattern_in_file_attribute = {
        'type': 'pattern-in-file', 'object_relation': 'pattern-in-file'
    }

    # OBJECTS MAPPING
    __file_hashes_mapping = Mapping(
        **{
            'AUTHENTIHASH': __authentihash_attribute,
            'IMPHASH': STIX2Mapping.imphash_attribute(),
            'MD5': STIX2Mapping.md5_attribute(),
            'SHA1': STIX2Mapping.sha1_attribute(),
            'SHA-1': STIX2Mapping.sha1_attribute(),
            'SHA224': __sha224_attribute,
            'SHA256': STIX2Mapping.sha256_attribute(),
            'SHA-256': STIX2Mapping.sha256_attribute(),
            'SHA3224': __sha3_224_attribute,
            'SHA3-256': STIX2Mapping.sha3_256_attribute(),
            'SHA3384': __sha3_384_attribute,
            'SHA3-512': STIX2Mapping.sha3_512_attribute(),
            'SHA384': __sha384_attribute,
            'SHA512': STIX2Mapping.sha512_attribute(),
            'SHA-512': STIX2Mapping.sha512_attribute(),
            'ssdeep': STIX2Mapping.ssdeep_attribute(),
            'SSDEEP': STIX2Mapping.ssdeep_attribute(),
            'TELFHASH': __telfhash_attribute,
            'TLSH': STIX2Mapping.tlsh_attribute(),
            'VHASH': __vhash_attribute
        }
    )
    __file_object_mapping = Mapping(
        accessed=STIX2Mapping.access_time_attribute(),
        atime=STIX2Mapping.access_time_attribute(),
        created=STIX2Mapping.creation_time_attribute(),
        ctime=STIX2Mapping.creation_time_attribute(),
        mime_type=STIX2Mapping.mime_type_attribute(),
        modified=STIX2Mapping.modification_time_attribute(),
        mtime=STIX2Mapping.modification_time_attribute(),
        name=STIX2Mapping.filename_attribute(),
        name_enc=STIX2Mapping.file_encoding_attribute(),
        size=STIX2Mapping.size_in_bytes_attribute(),
        x_misp_attachment=InternalSTIX2Mapping.attachment_attribute(),
        x_misp_certificate=__certificate_attribute,
        x_misp_compilation_timestamp=__compilation_timestamp_attribute,
        x_misp_entropy=STIX2Mapping.entropy_attribute(),
        x_misp_fullpath=__fullpath_attribute,
        x_misp_path=STIX2Mapping.path_attribute(),
        x_misp_pattern_in_file=__pattern_in_file_attribute,
        x_misp_state=InternalSTIX2Mapping.state_attribute(),
        x_misp_text=STIX2Mapping.text_attribute()
    )

    @classmethod
    def file_hashes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__file_hashes_mapping.get(field)

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping


class STIX2ObservableConverter:
    def _parse_artifact_observable(
            self, artifact_object: MISPObject, artifact: Artifact):
        if hasattr(artifact, 'hashes'):
            for hash_type, value in artifact.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                artifact_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.artifact_object_mapping().items():
            if hasattr(artifact, field):
                self.main_parser._populate_object_attributes(
                    artifact_object, mapping, getattr(artifact, field)
                )

    def _parse_file_observable(self, file_object: MISPObject, _file: File):
        if hasattr(_file, 'hashes'):
            for hash_type, value in _file.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                file_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.file_object_mapping().items():
            if hasattr(_file, field):
                self.main_parser._populate_object_attributes(
                    file_object, mapping, getattr(_file, field)
                )

    def _parse_software_observable(
            self, software_object: MISPObject, software: Software):
        for field, mapping in self._mapping.software_object_mapping().items():
            if hasattr(software, field):
                self.main_parser._populate_object_attributes(
                    software_object, mapping, getattr(software, field)
                )


class STIX2ObservableObjectConverter(STIX2Converter, STIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2ObservableMapping

    def _create_misp_object_from_observable_object(
            self, name: str, observable: _OBSERVABLE_TYPING) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        self.main_parser._sanitise_object_uuid(
            misp_object, observable.get('id')
        )
        return misp_object

    def _parse_artifact_observable(self, artifact_ref: str) -> MISPObject:
        observable = self.main_parser._observable[artifact_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable_object(
            'artifact', artifact
        )
        super()._parse_artifact_observable(artifact_object, artifact)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_file_observable(self, file_ref: str) -> MISPObject:
        observable = self.main_parser._observable[file_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable_object(
            'file', _file
        )
        super()._parse_file_observable(file_object, _file)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(file_object, _file)
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_software_observable(self, software_ref: str) -> MISPObject:
        observable = self.main_parser._observable[software_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable_object(
            'software', software
        )
        super()._parse_software_observable(software_object, software)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
        )
        observable['misp_object'] = misp_object
        return misp_object


class STIX2SampleObservableConverter(
        STIX2ObservableConverter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_CONVERTER_TYPING):
        self._main_converter = main

    @property
    def event_uuid(self) -> str:
        return self.main_parser.misp_event.uuid

    @property
    def main_parser(self) -> 'ExternalSTIX2toMISPParser':
        return self._main_converter.main_parser

    def _create_misp_object_from_observable(
            self, name: str, observable: _OBSERVABLE_TYPING,
            malware: Malware) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        self.main_parser._sanitise_object_uuid(
            misp_object, observable.get('id')
        )
        misp_object.from_dict(**self._main_converter._parse_timeline(malware))
        return misp_object

    def _parse_artifact_observable(
            self, artifact_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[artifact_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable(
            'artifact', artifact, malware
        )
        super()._parse_artifact_observable(artifact_object, artifact)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_file_observable(
            self, file_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[file_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable(
            'file', _file, malware
        )
        super()._parse_file_observable(file_object, _file)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(file_object, _file)
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_software_observable(
            self, software_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[software_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable(
            'software', software, malware
        )
        super()._parse_software_observable(software_object, software)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
        )
        observable['misp_object'] = misp_object
        return misp_object


class ExternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'ExternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = ExternalSTIX2ObservableMapping


class InternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'InternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = InternalSTIX2ObservableMapping
