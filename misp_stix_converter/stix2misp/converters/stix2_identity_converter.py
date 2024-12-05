#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter,
    _MAIN_PARSER_TYPING)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPGalaxyCluster, MISPObject
from stix2.v20.sdo import Identity as Identity_v20
from stix2.v21.sdo import Identity as Identity_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_IDENTITY_TYPING = Union[
    Identity_v20, Identity_v21
]


class STIX2IdentityMapping(STIX2Mapping, metaclass=ABCMeta):
    __contact_information_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'contact_information'}
    )
    __role_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'role'}
    )
    __roles_attribute = {'type': 'text', 'object_relation': 'roles'}
    __organization_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        description=STIX2Mapping.description_attribute(),
        roles=__role_attribute,
        sectors={'type': 'text', 'object_relation': 'sector'}
    )
    __identity_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        description=STIX2Mapping.description_attribute(),
        contact_information=__contact_information_attribute,
        identity_class={'type': 'text', 'object_relation': 'identity_class'},
        sectors={'type': 'text', 'object_relation': 'sectors'},
        roles=__roles_attribute,
        x_misp_roles=__roles_attribute
    )

    @classmethod
    def contact_information_attribute(cls) -> dict:
        return cls.__contact_information_attribute

    @classmethod
    def identity_object_mapping(cls) -> dict:
        return cls.__identity_object_mapping

    @classmethod
    def organization_object_mapping(cls) -> dict:
        return cls.__organization_object_mapping

    @classmethod
    def role_attribute(cls) -> dict:
        return cls.__role_attribute


class STIX2IdentityConverter(STIX2Converter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)

    def _create_cluster(self, identity: _IDENTITY_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        sector_args = self._create_cluster_args(
            identity, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(identity)
        if meta:
            sector_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(**sector_args)

    def _parse_identity_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._create_misp_object('identity', identity)
        for attribute in self._generic_parser(identity):
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, identity)


class ExternalSTIX2IdentityMapping(STIX2IdentityMapping, ExternalSTIX2Mapping):
    __organization_object_mapping = Mapping(
        **STIX2IdentityMapping.organization_object_mapping(),
        contact_information=STIX2IdentityMapping.contact_information_attribute()
    )

    @classmethod
    def organization_object_mapping(cls) -> dict:
        return cls.__organization_object_mapping


class ExternalSTIX2IdentityConverter(
        STIX2IdentityConverter, ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2IdentityMapping

    def parse(self, identity_ref: str):
        if identity_ref not in self.main_parser._creators:
            identity = self.main_parser._get_stix_object(identity_ref)
            if getattr(identity, 'identity_class', None) == 'class':
                self._parse_galaxy(identity, 'sector')
            else:
                name = self._fetch_identity_object_name(identity)
                getattr(self, f'_parse_{name}_object')(identity)
                misp_object = self._create_misp_object(name, identity)
                for attribute in self._generic_parser(identity, name):
                    misp_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(misp_object, identity)

    @staticmethod
    def _fetch_identity_object_name(identity: _IDENTITY_TYPING) -> str:
        if getattr(identity, 'identity_class', None) == 'organization':
            return 'organization'
        return 'identity'

    def _parse_organization_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._create_misp_object('organization', identity)
        for attribute in self._generic_parser(identity, 'organization'):
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, identity)


class InternalSTIX2IdentityMapping(STIX2IdentityMapping, InternalSTIX2Mapping):
    __employee_type_attribute = {
        'type': 'text', 'object_relation': 'employee-type'
    }
    __link_type = {'type': 'link'}
    __phone_number_type = {'type': 'phone-number'}
    __src_email_type = {'type': 'email-src'}
    __text_type = {'type': 'text'}

    __employee_object_mapping = Mapping(
        name={'type': 'full-name', 'object_relation': 'full-name'},
        description={'type': 'text', 'object_relation': 'text'},
        roles=__employee_type_attribute,
        x_misp_business_unit={
            'type': 'target-org', 'object_relation': 'business_unit'
        },
        x_misp_employee_type=__employee_type_attribute,
        x_misp_first_name={
            'type': 'first-name', 'object_relation': 'first-name'
        },
        x_misp_last_name={'type': 'last-name', 'object_relation': 'last-name'},
        x_misp_primary_asset={
            'type': 'target-machine', 'object_relation': 'primary-asset'
        },
        x_misp_userid={'type': 'target-user', 'object_relation': 'userid'}
    )
    __legal_entity_contact_information_mapping = Mapping(
        **{
            'phone-number': __phone_number_type,
            'website': __link_type
        }
    )
    __legal_entity_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        description=InternalSTIX2Mapping.text_attribute(),
        sectors={'type': 'text', 'object_relation': 'business'},
        x_misp_commercial_name={
            'type': 'text', 'object_relation': 'commercial-name'
        },
        x_misp_legal_form={'type': 'text', 'object_relation': 'legal-form'},
        x_misp_registration_number={
            'type': 'text', 'object_relation': 'registration-number'
        }
    )
    __news_agency_contact_information_mapping = Mapping(
        **{
            'address': __text_type,
            'e-mail': __src_email_type,
            'fax-number': __phone_number_type,
            'link': __link_type,
            'phone-number': __phone_number_type
        }
    )
    __news_agency_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        x_misp_alias=STIX2Mapping.alias_attribute(),
        x_misp_archive=InternalSTIX2Mapping.archive_attribute(),
        x_misp_url=STIX2Mapping.url_attribute()
    )
    __organization_contact_information_mapping = Mapping(
        **{
            'address': __text_type,
            'e-mail': __src_email_type,
            'fax-number': __phone_number_type,
            'phone-number': __phone_number_type
        }
    )
    __organization_object_mapping = Mapping(
        **STIX2IdentityMapping.organization_object_mapping(),
        x_misp_role=STIX2IdentityMapping.role_attribute(),
        x_misp_alias=STIX2Mapping.alias_attribute(),
        x_misp_date_of_inception={
            'type': 'datetime', 'object_relation': 'date-of-inception'
        },
        x_misp_type_of_organization={
            'type': 'text', 'object_relation': 'type-of-organization'
        },
        x_misp_VAT={'type': 'text', 'object_relation': 'VAT'}
    )
    __person_contact_information_mapping = Mapping(
        **{
            'address': __text_type,
            'e-mail': __src_email_type,
            'fax-number': __phone_number_type,
            'phone-number': __phone_number_type
        }
    )
    __person_object_mapping = Mapping(
        name={'type': 'text', 'object_relation': 'full-name'},
        description=InternalSTIX2Mapping.text_attribute(),
        roles=STIX2IdentityMapping.role_attribute(),
        x_misp_role=STIX2IdentityMapping.role_attribute(),
        x_misp_alias=STIX2Mapping.alias_attribute(),
        x_misp_birth_certificate_number={
            'type': 'text', 'object_relation': 'birth-certificate-number'
        },
        x_misp_date_of_birth={
            'type': 'date-of-birth', 'object_relation': 'date-of-birth'
        },
        x_misp_function={'type': 'text', 'object_relation': 'function'},
        x_misp_gender={'type': 'gender', 'object_relation': 'gender'},
        x_misp_handle={'type': 'text', 'object_relation': 'handle'},
        x_misp_identity_card_number={
            'type': 'identity-card-number',
            'object_relation': 'identity-card-number'
        },
        x_misp_instant_messaging_used={
            'type': 'text', 'object_relation': 'instant-messaging-used'
        },
        x_misp_nationality={
            'type': 'nationality', 'object_relation': 'nationality'
        },
        x_misp_occupation={'type': 'text', 'object_relation': 'occupation'},
        x_misp_passport_country={
            'type': 'passport-country', 'object_relation': 'passport-country'
        },
        x_misp_passport_creation={
            'type': 'passport-creation', 'object_relation': 'passport-creation'
        },
        x_misp_passport_expiration={
            'type': 'passport-expiration',
            'object_relation': 'passport-expiration'
        },
        x_misp_passport_number={
            'type': 'passport-number', 'object_relation': 'passport-number'
        },
        x_misp_place_of_birth={
            'type': 'place-of-birth', 'object_relation': 'place-of-birth'
        },
        x_misp_social_security_number={
            'type': 'text', 'object_relation': 'social-security-number'
        },
        x_misp_title={'type': 'text', 'object_relation': 'title'}
    )

    @classmethod
    def employee_object_mapping(cls) -> dict:
        return cls.__employee_object_mapping

    @classmethod
    def legal_entity_contact_information_mapping(
            cls, field: str) -> Union[str, None]:
        return cls.__legal_entity_contact_information_mapping.get(field)

    @classmethod
    def legal_entity_object_mapping(cls) -> dict:
        return cls.__legal_entity_object_mapping

    @classmethod
    def news_agency_contact_information_mapping(
            cls, field: str) -> Union[str, None]:
        return cls.__news_agency_contact_information_mapping.get(field)

    @classmethod
    def news_agency_object_mapping(cls) -> dict:
        return cls.__news_agency_object_mapping

    @classmethod
    def organization_contact_information_mapping(
            cls, field: str) -> Union[str, None]:
        return cls.__organization_contact_information_mapping.get(field)

    @classmethod
    def organization_object_mapping(cls) -> dict:
        return cls.__organization_object_mapping

    @classmethod
    def person_contact_information_mapping(cls, field: str) -> Union[str, None]:
        return cls.__person_contact_information_mapping.get(field)

    @classmethod
    def person_object_mapping(cls) -> dict:
        return cls.__person_object_mapping


class InternalSTIX2IdentityConverter(
        STIX2IdentityConverter, InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2IdentityMapping

    def parse(self, identity_ref: str):
        if identity_ref not in self.main_parser._creators:
            identity = self.main_parser._get_stix_object(identity_ref)
            feature = self._handle_mapping_from_labels(
                identity.labels, identity.id
            )
            try:
                parser = getattr(self, feature)
            except AttributeError:
                raise UnknownParsingFunctionError(feature)
            try:
                parser(identity)
            except Exception as exception:
                _traceback = self.main_parser._parse_traceback(exception)
                self.main_parser._add_error(
                    'Error while parsing the Identity object with id '
                    f'{identity.id}: {_traceback}'
                )

    def _parse_employee_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._create_misp_object('employee', identity)
        for attribute in self._generic_parser(identity, 'employee'):
            misp_object.add_attribute(**attribute)
        if hasattr(identity, 'contact_information'):
            object_relation, value = identity.contact_information.split(': ')
            misp_object.add_attribute(
                **{
                    'type': 'target-email', 'value': value,
                    'object_relation': object_relation,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{identity.id} - {object_relation} - {value}'
                    )
                }
            )
        self.main_parser._add_misp_object(misp_object, identity)
    
    def _parse_identity_object_attributes(
            self, identity: _IDENTITY_TYPING, name: str) -> MISPObject:
        misp_object = self._create_misp_object(name, identity)
        feature = name.replace('-', '_')
        for attribute in self._generic_parser(identity, feature):
            misp_object.add_attribute(**attribute)
        if hasattr(identity, 'contact_information'):
            mapping = getattr(
                self._mapping, f'{feature}_contact_information_mapping'
            )
            contact_information = []
            for contact_info in identity.contact_information.split(' / '):
                if ': ' in contact_info:
                    try:
                        object_relation, value = contact_info.split(': ')
                    except ValueError:
                        contact_information.append(contact_info)
                        continue
                    attribute = mapping(object_relation)
                    if attribute is not None:
                        misp_object.add_attribute(
                            **{
                                'value': value, **attribute,
                                'object_relation': object_relation,
                                'uuid': self.main_parser._create_v5_uuid(
                                    f'{identity.id} - {object_relation}'
                                    f' - {value}'
                                )
                            }
                        )
                        continue
                contact_information.append(contact_info)
            if contact_information:
                misp_object.add_attribute(
                    'contact_information', '; '.join(contact_information)
                )
        return misp_object

    def _parse_legal_entity_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object_attributes(
            identity, 'legal-entity'
        )
        if hasattr(identity, 'x_misp_logo'):
            misp_object.add_attribute(
                **self._populate_object_attribute(
                    {'type': 'attachment', 'object_relation': 'logo'},
                    f'{identity.id} - logo', identity.x_misp_logo
                )
            )
        self.main_parser._add_misp_object(misp_object, identity)

    def _parse_news_agency_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object_attributes(
            identity, 'news-agency'
        )
        if hasattr(identity, 'x_misp_attachment'):
            misp_object.add_attribute(
                **self._populate_object_attribute(
                    {'type': 'attachment', 'object_relation': 'attachment'},
                    f'{identity.id} - attachment', identity.x_misp_attachment
                )
            )
        self.main_parser._add_misp_object(misp_object, identity)

    def _parse_organization_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object_attributes(
            identity, 'organization'
        )
        self.main_parser._add_misp_object(misp_object, identity)

    def _parse_person_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object_attributes(identity, 'person')
        if hasattr(identity, 'x_misp_portrait'):
            misp_object.add_attribute(
                **self._populate_object_attribute(
                    {'type': 'attachment', 'object_relation': 'portrait'},
                    f'{identity.id} - porttrait', identity.x_misp_portrait
                )
            )
        self.main_parser._add_misp_object(misp_object, identity)
