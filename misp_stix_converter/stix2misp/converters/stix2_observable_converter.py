#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2mapping import InternalSTIX2Mapping, STIX2Mapping
from abc import ABCMeta
from pymisp import MISPObject
from stix2.v21.sdo import Malware
from typing import Union

_MAIN_CONVERTER_TYPING = Union[
    'ExternalSTIX2MalwareConverter', 'InternalSTIX2MalwareConverter'
]


class STIX2SampleObservableMapping:
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


class ExternalSTIX2SampleObservableMapping(STIX2SampleObservableMapping):
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


class InternalSTIX2SampleObservableMapping(STIX2SampleObservableMapping):
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


class STIX2SampleObservableConverter(metaclass=ABCMeta):
    def __init__(self, main: _MAIN_CONVERTER_TYPING):
        self._main_converter = main

    @property
    def main_parser(self):
        return self._main_converter.main_parser

    def _parse_artifact_observable(
            self, artifact_ref: str, malware: Malware) -> MISPObject:
        artifact = self.main_parser._observable[artifact_ref]
        misp_object = self._main_converter._create_misp_object_from_observable(
            'artifact', artifact, malware
        )
        if hasattr(artifact, 'hashes'):
            for hash_type, value in artifact.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                misp_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.artifact_object_mapping().items():
            if hasattr(artifact, field):
                self._maing_converter._populate_object_attributes(
                    misp_object, mapping, getattr(artifact, field)
                )
        return self._main_parser._add_misp_object(misp_object, artifact)

    def _parse_file_observable(
            self, file_ref: str, malware: Malware) -> MISPObject:
        file_object = self.main_parser._observable[file_ref]
        misp_object = self._main_converter._create_misp_object_from_observable(
            'file', file_object, malware
        )
        if hasattr(file_object, 'hashes'):
            for hash_type, value in file_object.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                misp_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.file_object_mapping().items():
            if hasattr(file_object, field):
                self._main_converter._populate_object_attributes(
                    misp_object, mapping, getattr(file_object, field)
                )
        return self.main_parser._add_misp_object(misp_object, file_object)

    def _parse_software_observable(
            self, software_ref: str, malware: Malware) -> MISPObject:
        software = self.main_parser._observable[software_ref]
        misp_object = self._main_converter._create_misp_object_from_observable(
            'software', software, malware
        )
        for field, mapping in self._mapping.software_object_mapping().items():
            if hasattr(software, field):
                self._main_converter._populate_object_attributes(
                    misp_object, mapping, getattr(software, field)
                )
        return self.main_parser._add_misp_object(misp_object, software)


class ExternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'ExternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = ExternalSTIX2SampleObservableMapping()


class InternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'InternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = InternalSTIX2SampleObservableMapping()
