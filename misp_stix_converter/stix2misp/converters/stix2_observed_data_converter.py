#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import (
    UndefinedObservableError, UndefinedSTIXObjectError,
    UnknownObservableMappingError, UnknownParsingFunctionError)
from .stix2_observable_converter import (
    ExternalSTIX2ObservableConverter, ExternalSTIX2ObservableMapping,
    InternalSTIX2ObservableConverter, InternalSTIX2ObservableMapping,
    STIX2ObservableConverter, _AUTONOMOUS_SYSTEM_TYPING, _DIRECTORY_TYPING,
    _EXTENSION_TYPING, _NETWORK_TRAFFIC_TYPING, _PROCESS_TYPING)
from .stix2converter import (_MAIN_PARSER_TYPING)
from abc import ABCMeta
from collections import defaultdict
from pymisp import MISPObject
from stix2.v20.sdo import ObservedData as ObservedData_v20
from stix2.v21.sdo import ObservedData as ObservedData_v21
from typing import Iterator, Optional, Tuple, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_OBSERVED_DATA_TYPING = Union[
    ObservedData_v20, ObservedData_v21
]


class STIX2ObservedDataConverter(STIX2ObservableConverter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)



class InternalSTIX2ObservedDataConverter(
        STIX2ObservedDataConverter, InternalSTIX2ObservableConverter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2ObservableMapping

    def parse(self, observed_data_ref: str):
        observed_data = self.main_parser._get_stix_object(observed_data_ref)
        try:
            feature = self._handle_mapping_from_labels(
                observed_data.labels, observed_data.id
            )
        except UndefinedSTIXObjectError as error:
            raise UndefinedObservableError(error)
        version = getattr(observed_data, 'spec_version', '2.0')
        to_call = f"{feature}_observable_v{version.replace('.', '')}"
        try:
            parser = getattr(self, to_call)
        except AttributeError:
            raise UnknownParsingFunctionError(to_call)
        try:
            parser(observed_data)
        except UnknownObservableMappingError as observable_types:
            self.main_parser._observable_mapping_error(
                observed_data.id, observable_types
            )

    ############################################################################
    #                        ATTRIBUTES PARSING METHODS                        #
    ############################################################################

    def _attribute_from_address_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        for observable_object in observed_data.objects.values():
            if '-addr' in observable_object.type:
                attribute['value'] = observable_object.value
                break
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_address_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        for reference in observed_data.object_refs:
            if '-addr' in reference:
                observable = self._fetch_observables(reference)
                attribute['value'] = observable.value
                break
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = self._parse_AS_value(observable.number)
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = self._parse_AS_value(observable.number)
        self.main_parser._add_misp_attribute(attribute, observed_data)

    @staticmethod
    def _attribute_from_attachment_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = observable.name
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        self.main_parser._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_attachment_observable(
                    tuple(observed_data.objects.values())
                )
            ),
            observed_data
        )

    def _attribute_from_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = self._fetch_observables(observed_data.object_refs)
        if isinstance(observables, tuple):
            attribute.update(
                self._attribute_from_attachment_observable(observables)
            )
        else:
            attribute['value'] = observables.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{address.value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f'{domain.value}|{address.value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['1'].name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs[1])
        attribute['value'] = observable.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].body
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.body
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].received_lines[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.received_lines[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_message_id_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.message_id
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['Reply-To']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.additional_header_fields['Reply-To']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].subject
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.subject
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['X-Mailer']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.additional_header_fields['X-Mailer']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].value
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs[0])
        attribute['value'] = observable.value
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_github_username_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.account_login
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = list(observed_data.objects['0'].hashes.values())[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = list(observable.hashes.values())[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_ip_port_observable(
            self, network_traffic :_NETWORK_TRAFFIC_TYPING,
            ip_value: str, observed_data: _OBSERVED_DATA_TYPING):
        attribute = self._create_attribute_dict(observed_data)
        for feature in ('src_port', 'dst_port'):
            if hasattr(network_traffic, feature):
                port_value = getattr(network_traffic, feature)
                attribute['value'] = f'{ip_value}|{port_value}'
                self.main_parser._add_misp_attribute(attribute, observed_data)
                break

    def _attribute_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._attribute_from_ip_port_observable(
            observed_data.objects['0'], observed_data.objects['1'].value,
            observed_data
        )

    def _attribute_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        network, address = self._fetch_observables(
            observed_data.object_refs
        )
        self._attribute_from_ip_port_observable(
            network, address.value, observed_data
        )

    @staticmethod
    def _attribute_from_malware_sample_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = (
                    f"{observable.name}|{observable.hashes['MD5']}"
                )
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_malware_sample_observable_v20(
            self, observed_data: ObservedData_v20):
        self.main_parser._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_malware_sample_observable(
                    observed_data.objects.values()
                )
            ),
            observed_data
        )

    def _attribute_from_malware_sample_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = self._fetch_observables(observed_data.object_refs)
        if isinstance(observables, tuple):
            attribute.update(
                self._attribute_from_malware_sample_observable(observables)
            )
        else:
            attribute['value'] = (
                f"{observables.name}|{observables.hashes['MD5']}"
            )
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].key
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.key
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self.main_parser._add_misp_attribute(attribute, observed_data)

    ############################################################################
    #                       MISP OBJECTS PARSING METHODS                       #
    ############################################################################

    def _object_from_account_with_attachment_observable(
            self, observed_data: _OBSERVED_DATA_TYPING,
            name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_generic_observable_with_data(
            observable, name.replace('-', '_'), observed_data.id
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_android_app_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'android-app', 'v20'
        )

    def _object_from_android_app_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'android-app', 'v21'
        )

    def _object_from_asn_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('asn', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_asn_observable(
            observable, getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_asn_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_asn_observable(observed_data, 'v20')

    def _object_from_asn_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_asn_observable(observed_data, 'v21')

    def _object_from_cpe_asset_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'cpe-asset', 'v20')

    def _object_from_cpe_asset_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'cpe-asset', 'v21')

    def _object_from_credential_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'credential', 'v20'
        )

    def _object_from_credential_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'credential', 'v21'
        )

    def _object_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        mapping = self._mapping.domain_ip_object_mapping
        ip_parsed = set()
        for observable in observed_data.objects.values():
            if observable.type == 'domain-name':
                for field, attribute in mapping().items():
                    if hasattr(observable, field):
                        attributes = self._populate_object_attributes(
                            attribute, getattr(observable, field),
                            observed_data.id
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in ip_parsed:
                            continue
                        value = observed_data.objects[reference].value
                        misp_object.add_attribute(
                            **{
                                'value': value, **self._mapping.ip_attribute(),
                                'uuid': self.main_parser._create_v5_uuid(
                                    f'{observed_data.id} - ip - {value}'
                                )
                            }
                        )
                        ip_parsed.add(reference)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        ip_parsed = set()
        for object_ref in observed_data.object_refs:
            if object_ref.startswith('domain-name--'):
                observable = self.main_parser._observable[object_ref]
                for attribute in self._parse_domain_ip_observable(observable):
                    misp_object.add_attribute(**attribute)
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in ip_parsed:
                            continue
                        address = self.main_parser._observable[reference]
                        misp_object.add_attribute(
                            **{
                                'value': address.value,
                                **self._mapping.ip_attribute(),
                                **self.main_parser._sanitise_attribute_uuid(
                                    address.id
                                )
                            }
                        )
                        ip_parsed.add(reference)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('email', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'email-message':
                continue
            if hasattr(observable, 'from_ref'):
                address = observables[observable.from_ref]
                attributes = self._parse_email_reference_observable(
                    address, 'from', getattr(address, 'id', observed_data.id)
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            for feature in ('to', 'cc', 'bcc'):
                if hasattr(observable, f'{feature}_refs'):
                    for reference in getattr(observable, f'{feature}_refs'):
                        address = observables[reference]
                        attributes = self._parse_email_reference_observable(
                            address, feature,
                            getattr(address, 'id', observed_data.id)
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
            object_id = getattr(observable, 'id', observed_data.id)
            attributes = self._parse_generic_observable(
                observable, 'email', object_id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            if hasattr(observable, 'additional_header_fields'):
                attributes = self._parse_email_additional_header(
                    observable, object_id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            if hasattr(observable, 'body_multipart'):
                for body_part in observable.body_multipart:
                    relation, value = body_part.content_disposition.split(';')
                    feature = (
                        'email_attachment' if relation == 'attachment'
                        else 'attachment'
                    )
                    reference = observables[body_part.body_raw_ref]
                    attributes = self._parse_email_body_observable(
                        reference, feature, value,
                        getattr(reference, 'id', observed_data.id)
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_email_observable(observed_data, 'v20')

    def _object_from_email_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_email_observable(observed_data, 'v21')

    def _object_from_facebook_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v20'
        )

    def _object_from_facebook_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v21'
        )

    def _object_from_file_extension_observable(
            self, extension: _EXTENSION_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, object_id: str) -> str:
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(
            uuid=self.main_parser._create_v5_uuid(
                f'{observed_data.id} - windows-pebinary-ext'
            ),
            **self._parse_timeline(observed_data)
        )
        attributes = self._parse_pe_extension_observable(
            extension, f'{object_id} - windows-pebinary-ext'
        )
        for attribute in attributes:
            pe_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(pe_object, observed_data)
        if hasattr(extension, 'sections'):
            for index, section in enumerate(extension.sections):
                section_object = self._create_misp_object('pe-section')
                section_object.from_dict(
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - section #{index}'
                    ),
                    **self._parse_timeline(observed_data)
                )
                attributes = self._parse_pe_section_observable(
                    section, f'{object_id} - section #{index}'
                )
                for attribute in attributes:
                    section_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(section_object, observed_data)
                misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _object_from_file_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        file_object = self._create_misp_object('file', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            object_id = getattr(observable, 'id', observed_data.id)
            attributes = self._parse_file_observable(observable, object_id)
            for attribute in attributes:
                file_object.add_attribute(**attribute)
            if hasattr(observable, 'parent_directory_ref'):
                file_object.add_attribute(
                    **self._parse_file_parent_observable(
                        observables[observable.parent_directory_ref],
                        observed_data.id
                    )
                )
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                attribute = {
                    'value': artifact.x_misp_filename,
                    'data': artifact.payload_bin
                }
                if getattr(artifact, 'hashes', {}).get('MD5') is not None:
                    attribute['value'] += f"|{artifact.hashes['MD5']}"
                    attribute.update(self._mapping.malware_sample_attribute())
                else:
                    attribute.update(self._mapping.attachment_attribute())
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(artifact.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f"{observed_data.id} - {attribute['type']}"
                        f" - {attribute['value']}"
                    )
                file_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                file_object, observed_data
            )
            if getattr(observable, 'extensions', {}).get('windows-pebinary-ext'):
                pe_uuid = self._object_from_file_extension_observable(
                    observable.extensions['windows-pebinary-ext'],
                    observed_data, object_id
                )
                misp_object.add_reference(pe_uuid, 'includes')

    def _object_from_file_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_file_observable(observed_data, 'v20')

    def _object_from_file_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_file_observable(observed_data, 'v21')

    def _object_from_generic_observable(
            self, observed_data: _OBSERVED_DATA_TYPING,
            name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_generic_observable(
            observable, name.replace('-', '_'),
            getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_github_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v20'
        )

    def _object_from_github_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v21'
        )

    def _object_from_gitlab_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'gitlab-user', 'v20'
        )

    def _object_from_gitlab_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'gitlab-user', 'v21'
        )

    def _object_from_http_request_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('http-request', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type == 'domain-name':
                attribute = {
                    'value': observable.value, **self._mapping.host_attribute()
                }
                if hasattr(observable, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(observable.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - host - {observable.value}'
                    )
                misp_object.add_attribute(**attribute)
                continue
            for feature in ('src', 'dst'):
                if hasattr(observable, f'{feature}_ref'):
                    address = observables[
                        getattr(observable, f'{feature}_ref')
                    ]
                    content = self._parse_network_traffic_reference_observable(
                        feature, address,
                        getattr(address, 'id', observed_data.id)
                    )
                    for attribute in content:
                        misp_object.add_attribute(**attribute)
            object_id = getattr(observable, 'id', observed_data.id)
            attributes = self._parse_generic_observable(
                observable, 'http_request', object_id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            if getattr(observable, 'extensions', {}).get('http-request-ext'):
                attributes = self._parse_http_request_extension_observable(
                    observable.extensions['http-request-ext'], object_id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_http_request_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_http_request_observable(observed_data, 'v20')

    def _object_from_http_request_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_http_request_observable(observed_data, 'v21')

    def _object_from_image_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('image', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type == 'file':
                attributes = self._parse_generic_observable(
                    observable, 'image', observed_data.id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            elif observable.type == 'artifact':
                if hasattr(observable, 'payload_bin'):
                    artifacts = self._parse_image_attachment_observable(
                        observable, observed_data.id
                    )
                    for attribute in artifacts:
                        misp_object.add_attribute(**attribute)
                elif hasattr(observable, 'url'):
                    urls = self._parse_image_url_observable(
                        observable, observed_data.id
                    )
                    for attribute in urls:
                        misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_image_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_image_observable(observed_data, 'v20')

    def _object_from_image_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_image_observable(observed_data, 'v21')

    def _object_from_ip_port_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('ip-port', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type == 'network-traffic':
                ip_protocols: set = set()
                for feature in ('src', 'dst'):
                    if hasattr(observable, f'{feature}_ref'):
                        ip_attribute = getattr(
                            self._mapping, f'ip_{feature}_attribute'
                        )
                        address = observables[
                            getattr(observable, f'{feature}_ref')
                        ]
                        ip_protocols.add(address.type.split('-')[0])
                        if hasattr(address, 'id'):
                            misp_object.add_attribute(
                                **{
                                    'value': address.value, **ip_attribute(),
                                    **self.main_parser._sanitise_attribute_uuid(
                                        address.id
                                    )
                                }
                            )
                            continue
                        misp_object.add_attribute(
                            **{
                                'value': address.value, **ip_attribute(),
                                'uuid': self.main_parser._create_v5_uuid(
                                    f'{observed_data.id} - ip-{feature}'
                                    f' - {address.value}'
                                )
                            }
                        )
                attributes = self._parse_generic_observable(
                    observable, 'ip_port', observed_data.id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
                for protocol in observable.protocols:
                    if protocol not in ip_protocols:
                        misp_object.add_attribute(
                            **{
                                'value': protocol,
                                **self._mapping.protocol_attribute()
                            }
                        )
                self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_ip_port_observable(observed_data, 'v20')

    def _object_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_ip_port_observable(observed_data, 'v21')

    def _object_from_lnk_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('lnk', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            attributes = self._parse_lnk_observable(
                observable, observed_data.id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            if hasattr(observable, 'parent_directory_ref'):
                misp_object.add_attribute(
                    **self._parse_file_parent_observable(
                        observables[observable.parent_directory_ref],
                        observed_data.id
                    )
                )
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                value = f"{artifact.x_misp_filename}|{artifact.hashes['MD5']}"
                attribute = {
                    'data': artifact.payload_bin, 'value': value,
                    **self._mapping.malware_sample_attribute()
                }
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(artifact.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - malware-sample - {value}'
                    )
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_lnk_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_lnk_observable(observed_data, 'v20')

    def _object_from_lnk_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_lnk_observable(observed_data, 'v21')

    def _object_from_mutex_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'mutex', 'v20')

    def _object_from_mutex_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'mutex', 'v21')

    def _object_from_netflow_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('netflow', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'network-traffic':
                continue
            for feature in ('src', 'dst'):
                if hasattr(observable, f'{feature}_ref'):
                    address = observables[getattr(observable, f'{feature}_ref')]
                    attribute = {
                        'value': address.value,
                        **getattr(self._mapping, f'ip_{feature}_attribute')()
                    }
                    if hasattr(address, 'id'):
                        attribute.update(
                            self.main_parser._sanitise_attribute_uuid(
                                address.id
                            )
                        )
                    else:
                        attribute['uuid'] = self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - ip-{feature}'
                            f' - {address.value}'
                        )
                    misp_object.add_attribute(**attribute)
                    if hasattr(address, 'belongs_to_refs'):
                        autonomous_systems = (
                            observables[reference] for reference
                            in getattr(address, 'belongs_to_refs')
                        )
                        attributes = self._parse_netflow_references(
                            feature, observed_data.id, *autonomous_systems
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
            attributes = self._parse_netflow_observable(
                observable, observed_data.id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_netflow_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_netflow_observable(observed_data, 'v20')

    def _object_from_netflow_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_netflow_observable(observed_data, 'v21')

    def _object_from_network_connection_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-connection', observed_data, observables,
                observable_id
            )
            attributes = self._parse_network_connection_observable(
                observable, getattr(observable, 'id', observed_data.id)
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_network_connection_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_connection_observable(observed_data, 'v20')

    def _object_from_network_connection_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_connection_observable(observed_data, 'v21')

    def _object_from_network_socket_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-socket', observed_data, observables, observable_id
            )
            attributes = self._parse_network_socket_observable(
                observable, getattr(observable, 'id', observed_data.id)
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_network_socket_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_socket_observable(observed_data, 'v20')

    def _object_from_network_socket_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_socket_observable(observed_data, 'v21')

    def _object_from_network_traffic_observable(
            self, name: str, observed_data: _OBSERVED_DATA_TYPING,
            observables: dict, observable_id: str) -> MISPObject:
        misp_object = self._create_misp_object(name, observed_data)
        observable = observables[observable_id]
        for asset in ('src', 'dst'):
            if hasattr(observable, f'{asset}_ref'):
                address = observables[getattr(observable, f'{asset}_ref')]
                attributes = self._parse_network_traffic_reference_observable(
                    asset, address, getattr(address, 'id', observed_data.id)
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
        attributes = self._parse_generic_observable(
            observable, name.replace('-', '_'),
            getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return misp_object

    def _object_from_parler_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v20'
        )

    def _object_from_parler_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v21'
        )

    def _object_from_process_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('process', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        main_process = self._fetch_main_process(observables)
        attributes = self._parse_process_observable(
            main_process, getattr(main_process, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        if hasattr(main_process, 'binary_ref'):
            image = observables[main_process.binary_ref]
            misp_object.add_attribute(
                **{
                    **self._mapping.image_attribute(),
                    'value': image.name,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - image - {image.name}'
                    )
                }
            )
        elif hasattr(main_process, 'image_ref'):
            image = observables[main_process.image_ref]
            misp_object.add_attribute(
                **{
                    'value': image.name,
                    **self._mapping.image_attribute(),
                    **self.main_parser._sanitise_attribute_uuid(image.id)
                }
            )
        if hasattr(main_process, 'child_refs'):
            for child_ref in main_process.child_refs:
                process = observables[child_ref]
                attribute = {
                    'value': process.pid,
                    **self._mapping.child_pid_attribute()
                }
                if hasattr(process, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(process.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - child-pid - {process.pid}'
                    )
                misp_object.add_attribute(**attribute)
        if hasattr(main_process, 'parent_ref'):
            parent_process = observables[main_process.parent_ref]
            object_id = getattr(parent_process, 'id', observed_data.id)
            mapping = self._mapping.parent_process_object_mapping
            for feature, attribute in mapping().items():
                if hasattr(parent_process, feature):
                    misp_object.add_attribute(
                        **{
                            **attribute,
                            'value': getattr(parent_process, feature),
                            'uuid': self.main_parser._create_v5_uuid(
                                f"{object_id} - {attribute['object_relation']}"
                                f" - {getattr(parent_process, feature)}"
                            )
                        }
                    )
                    misp_object.add_attribute(**attribute)
            if hasattr(parent_process, 'binary_ref'):
                image = observables[parent_process.binary_ref]
                misp_object.add_attribute(
                    **{
                        **self._mapping.parent_image_attribute(),
                        'value': image.name,
                        'uuid': self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - parent-image - {image.name}'
                        )
                    }
                )
            elif hasattr(parent_process, 'image_ref'):
                image = observables[parent_process.image_ref]
                misp_object.add_attribute(
                    **{
                        'value': image.name,
                        **self._mapping.parent_image_attribute(),
                        **self.main_parser._sanitise_attribute_uuid(image.id)
                    }
                )
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_process_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_process_observable(observed_data, 'v20')

    def _object_from_process_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_process_observable(observed_data, 'v21')

    def _object_from_reddit_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v20'
        )

    def _object_from_reddit_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v21'
        )

    def _object_from_registry_key_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('registry-key', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_registry_key_observable(
            observable, getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_registry_key_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_registry_key_observable(observed_data, 'v20')

    def _object_from_registry_key_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_registry_key_observable(observed_data, 'v21')

    def _object_from_telegram_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'telegram-account', 'v20'
        )

    def _object_from_telegram_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'telegram-account', 'v21'
        )

    def _object_from_twitter_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v20'
        )

    def _object_from_twitter_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v21'
        )

    def _object_from_url_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'url', 'v20')

    def _object_from_url_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'url', 'v21')

    def _object_from_user_account_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('user-account', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        object_id = getattr(observable, 'id', observed_data.id)
        attributes = self._parse_generic_observable_with_data(
            observable, 'user_account', object_id
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        if getattr(observable, 'extensions', {}).get('unix-account-ext'):
            attributes = self._parse_generic_observable(
                observable.extensions['unix-account-ext'],
                'unix_user_account_extension', object_id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_user_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_user_account_observable(observed_data, 'v20')

    def _object_from_user_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_user_account_observable(observed_data, 'v21')

    def _object_from_x509_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('x509', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        object_id = getattr(observable, 'id', observed_data.id)
        for attribute in self._parse_x509_observable(observable, object_id):
            misp_object.add_attribute(**attribute)
        if hasattr(observable, 'x509_v3_extensions'):
            extension = observable.x509_v3_extensions
            for values in extension.subject_alternative_name.split(','):
                key, value = values.split('=')
                mapping = self._mapping.x509_subject_alternative_name_mapping(
                    key
                )
                if mapping is not None:
                    misp_object.add_attribute(
                        **{
                            'value': value, **mapping,
                            'uuid': self.main_parser._create_v5_uuid(
                                f"{object_id} - {mapping['object_relation']}"
                                f" - {value}"
                            )
                        }
                    )
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_x509_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_x509_observable(observed_data, 'v20')

    def _object_from_x509_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_x509_observable(observed_data, 'v21')

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _fetch_main_process(observables: dict) -> _PROCESS_TYPING:
        observable_types = tuple(
            observable.type for observable in observables.values()
        )
        if observable_types.count('process') == 1:
            for observable in observables.values():
                if observable.type == 'process':
                    return observable
        ref_features = ('child_refs', 'parent_ref')
        for observable in observables.values():
            if observable.type != 'process':
                continue
            if any(hasattr(observable, feature) for feature in ref_features):
                return observable

    def _fetch_observables(self, object_refs: Union[list, str]):
        if isinstance(object_refs, str):
            return self.main_parser._observable[object_refs]
        if len(object_refs) == 1:
            return self.main_parser._observable[object_refs[0]]
        return tuple(
            self.main_parser._observable[object_ref]
            for object_ref in object_refs
        )

    @staticmethod
    def _fetch_observables_v20(observed_data: ObservedData_v20):
        observables = tuple(observed_data.objects.values())
        return observables[0] if len(observables) == 1 else observables

    def _fetch_observables_v21(self, observed_data: ObservedData_v21):
        return self._fetch_observables(observed_data.object_refs)

    @staticmethod
    def _fetch_observables_with_id_v20(observed_data: ObservedData_v20) -> dict:
        return observed_data.objects

    def _fetch_observables_with_id_v21(
            self, observed_data: ObservedData_v21) -> dict:
        return {
            reference: self.main_parser._observable[reference]
            for reference in observed_data.object_refs
        }

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            feature = 'aliases' if reference.get('source_name') == 'cve' else 'external_id'
            if reference.get('external_id'):
                meta[feature].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta
