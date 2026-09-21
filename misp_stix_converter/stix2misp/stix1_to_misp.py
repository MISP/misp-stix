# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from ..tools.misp_object_templates import (
    _rejected_name_note, _sanitise_template_name, _template_attribute_types,
    _template_description, _UNKNOWN_TEMPLATE_NAME)
from ..tools.stix1_loading_helpers import load_stix1_package
from .exceptions import MissingSTIXContentError
from .importparser import STIXtoMISPParser
from abc import ABCMeta
from base64 import b64decode, b64encode
from collections import defaultdict
from cybox.common import Hash
from cybox.objects import (
    account_object, address_object, artifact_object, as_object,
    custom_object, email_message_object, dns_record_object,
    domain_name_object, file_object,
    hostname_object, http_session_object, link_object, mutex_object,
    network_connection_object, network_socket_object, pipe_object,
    process_object, socket_address_object, system_object, uri_object,
    unix_user_account_object, user_account_object, whois_object,
    win_executable_file_object, win_registry_key_object, win_service_object,
    win_user_account_object, x509_certificate_object)
from operator import attrgetter
from pathlib import Path
from pymisp.abstract import misp_objects_path
from pymisp.api import describe_types
from pymisp import MISPAttribute, MISPObject
import re
from stix.coa import CourseOfAction
from stix.core import STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.ais import AISMarkingStructure
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from typing import Iterator, Optional, Union
from uuid import uuid4

_ADDRESS_TYPING = Union[address_object.Address, address_object.EmailAddress]
_NETWORK_PROPERTIES_TYPING = Union[
    network_connection_object.NetworkConnection,
    network_socket_object.NetworkSocket
]
_PROPERTIES_TYPING = Union[
    account_object.Authentication, email_message_object.EmailHeader,
    whois_object.WhoisEntry, whois_object.WhoisRegistrant
]
_PARTIAL_PROPERTIES_TYPING = Union[
    as_object.AS, process_object.Process, user_account_object.UserAccount,
    win_executable_file_object.WinExecutableFile, win_registry_key_object.WinRegistryKey,
    win_registry_key_object.RegistryValue
]
_SIMPLE_PROPERTIES_TYPING = Union[
    file_object.File, network_socket_object.NetworkSocket
]
_STIX_OBJECT_TYPING = Union[CourseOfAction, ThreatActor]
_MISP_types = describe_types['types']
# `blocksize:hash:hash`, the shape of an ssdeep value, both hashes in base64
_SSDEEP_PATTERN = re.compile(r'^\d+:[0-9A-Za-z+/]*:[0-9A-Za-z+/]*$')


class StixObjectTypeError(Exception):
    pass


class STIX1toMISPParser(STIXtoMISPParser, metaclass=ABCMeta):
    def __init__(self):
        super().__init__()
        # Every accumulator this parser keeps is created by the reset hook, so
        # a fresh instance starts from the state a reused one is put back into
        self._reset_bundle_state()

    def load_stix_package(self, stix_package: STIXPackage):
        self.__stix_package = stix_package

    def parse_stix_content(self, filename: Union[Path, str],
                           max_size: Optional[int] = None, **kwargs):
        self.__stix_package = load_stix1_package(filename, max_size=max_size)
        self.parse_stix_package(**kwargs)

    def _reset_bundle_state(self):
        # An instance parsing a second package must not carry the galaxies and
        # references of the first one into the event it builds from it. Called
        # at the top of `parse_stix_package` rather than at loading time, where
        # the STIX 2 parsers reset: `parse_stix_content` sets the package
        # itself instead of going through `load_stix_package`, so parsing is
        # the one step every entry into a conversion takes.
        super()._reset_bundle_state()
        self.__galaxies = set()
        self.__references = defaultdict(list)

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def galaxies(self) -> set:
        return self.__galaxies

    @property
    def references(self) -> dict:
        return self.__references

    @property
    def stix_package(self) -> STIXPackage:
        return self.__stix_package

    @property
    def stix_version(self) -> str:
        # python-stix names the package version field `version`. Loading a
        # document without one fails earlier, in mixbox, but a package built in
        # memory and handed to `load_stix_package` - what MISP core does - can
        # carry no version at all.
        return self.__stix_package.version or '1.1.1'

    ############################################################################
    #                PARSING METHODS USED BY BOTH CHILD CLASSES                #
    ############################################################################

    # Define type & value of an attribute or object in MISP
    def _handle_attribute_type(self, properties, is_object=False, title=None):
        xsi_type = properties._XSI_TYPE
        args = [properties]
        if xsi_type in ("FileObjectType", "PDFFileObjectType", "WindowsFileObjectType"):
            args.append(is_object)
        elif xsi_type == "ArtifactObjectType":
            args.append(title)
        parser = self._mapping.attribute_types_mapping(xsi_type)
        if parser is None:
            raise StixObjectTypeError(xsi_type)
        return getattr(self, parser)(*args)

    def _handle_attribute_case(self, attribute_type, attribute_value, data, attribute):
        if attribute_type in ('attachment', 'malware-sample'):
            attribute['data'] = data
        elif attribute_type == 'text':
            attribute['comment'] = data
        self.misp_event.add_attribute(attribute_type, attribute_value, **attribute)

    # The value returned by the indicators or observables parser is a list of dictionaries
    # These dictionaries are the attributes we add in an object, itself added in the MISP event
    def _handle_object_case(self, name, attribute_value, compl_data, to_ids=False, object_uuid=None, test_mechanisms=[], description=None, title=None):
        if not name:
            # An observable carrying nothing to name an object with is the
            # observable there is nothing to convert from
            self._unnamed_object_error(object_uuid)
            return
        misp_object = MISPObject(name, misp_objects_path_custom=misp_objects_path)
        if object_uuid:
            misp_object.uuid = object_uuid
        # The name is only final here - what the export wrote the object as
        # names it, not the Observable id - so the description the export
        # writes for an object carrying no comment is told from a comment
        # against the template of the object the content actually builds
        comment = self._read_object_comment(name, description, title)
        if comment is not None:
            misp_object.comment = comment
        for attribute in attribute_value:
            attribute['to_ids'] = to_ids
            misp_object.add_attribute(**attribute)
        if isinstance(compl_data, dict):
            if "rejected_name" in compl_data:
                self._record_rejected_template_name(
                    misp_object, compl_data['rejected_name']
                )
            # if some complementary data is a dictionary containing an uuid,
            # it means we are using it to add an object reference
            if "pe_uuid" in compl_data:
                misp_object.add_reference(compl_data['pe_uuid'], 'includes')
            if "process_uuid" in compl_data:
                for uuid in compl_data["process_uuid"]:
                    misp_object.add_reference(uuid, 'connected-to')
        if test_mechanisms:
            for test_mechanism in test_mechanisms:
                misp_object.add_reference(test_mechanism, 'detected-with')
        self.misp_event.add_object(misp_object)

    def _read_test_mechanisms(
            self, indicator: Indicator) -> Iterator[tuple[str, str]]:
        """Read the rules an Indicator carries as test mechanisms.

        A Yara mechanism carries one rule, a Snort one a list of them - the
        two python-stix shapes - and each rule reads as the MISP attribute
        type the mechanism maps to, with the rule text. A mechanism of a type
        the mapping does not know records an error and reads as nothing.

        :param indicator: the Indicator carrying the test mechanisms
        :return: the `(attribute_type, rule)` pairs, one per rule
        """
        for test_mechanism in indicator.test_mechanisms or ():
            attribute_type = self._mapping.test_mechanism_mapping(
                test_mechanism._XSI_TYPE
            )
            if attribute_type is None:
                self._add_error(
                    f'Unknown Test Mechanism type: {test_mechanism._XSI_TYPE}'
                )
                continue
            rules = getattr(test_mechanism, 'rules', None)
            if rules is None:
                rules = (test_mechanism.rule,)
            for rule in rules:
                value = getattr(rule, 'value', None)
                if value is not None:
                    yield attribute_type, value

    # Parse a course of action and add a MISP object to the event
    def _parse_course_of_action(self, course_of_action):
        if any(self._read_markings(getattr(course_of_action, 'handling', None))):
            self._object_markings_warning()
        misp_object = MISPObject('course-of-action', misp_objects_path_custom=misp_objects_path)
        misp_object.uuid = self._sanitise_uuid(course_of_action.id_)
        if course_of_action.title:
            attribute = {'type': 'text', 'object_relation': 'name',
                         'value': course_of_action.title}
            misp_object.add_attribute(**attribute)
        for prop, properties_key in self._mapping.course_of_action_mapping().items():
            if getattr(course_of_action, prop):
                attribute = {
                    'type': 'text', 'object_relation': prop.replace('_', ''),
                    'value': str(
                        attrgetter(f'{prop}.{properties_key}')(course_of_action)
                    )
                }
                misp_object.add_attribute(**attribute)
        if course_of_action.parameter_observables:
            for observable in course_of_action.parameter_observables.observables:
                properties = observable.object_.properties
                attribute = MISPAttribute()
                attribute.type, attribute.value, _ = self._handle_attribute_type(properties)
                referenced_uuid = str(uuid4())
                attribute.uuid = referenced_uuid
                self.misp_event.add_attribute(**attribute)
                misp_object.add_reference(referenced_uuid, 'observable', None, **attribute)
        self.misp_event.add_object(misp_object)

    ############################################################################
    #                   MARKING DEFINITIONS PARSING METHODS.                   #
    ############################################################################

    def _parse_AIS_marking(self, marking: AISMarkingStructure) -> Iterator[str]:
        for feature in ('is_proprietary', 'not_proprietary'):
            proprietary = getattr(marking, feature)
            if proprietary is None:
                continue
            yield self._build_tag(
                'ais-marking', 'AISMarking', feature.title()
            )
            if hasattr(proprietary, 'cisa_proprietary'):
                cisa_proprietary = (
                    'true' if proprietary.cisa_proprietary.numerator == 1
                    else 'false'
                )
                yield self._build_tag(
                    'ais-marking', 'CISA_Proprietary', cisa_proprietary
                )
            if hasattr(proprietary, 'ais_consent'):
                yield self._build_tag(
                    'ais-marking', 'AISConsent', proprietary.ais_consent.consent
                )
            if hasattr(proprietary, 'tlp_marking'):
                yield self._build_tag(
                    'ais-marking', 'TLPMarking', proprietary.tlp_marking.color
                )

    def _read_markings(self, handling: Optional[Marking]) -> Iterator[str]:
        """Read every tag the Handling of a STIX object carries.

        A Handling holds one Marking Specification per set of markings, and
        the export writes a single one holding a TLP structure for the TLP
        tags and a Simple Marking per other tag. The colour comes back as a
        Built Tag, the statements as Copied Tags.

        :param handling: the Handling, None where the object carries none
        :return: the tags, in the order the markings hold them
        """
        for marking_specification in handling or ():
            yield from self._parse_marking(marking_specification)

    def _parse_marking(self, handling: MarkingSpecification) -> Iterator[str]:
        if getattr(handling, 'marking_structures', None):
            for marking in handling.marking_structures:
                parser = self._mapping.marking_mapping(marking._XSI_TYPE)
                if parser is not None:
                    # A marking field a taxonomy tag can be made of nothing
                    # from writes no tag: the builder returns None and the
                    # marking is dropped here, as at every other site that
                    # collects built tags rather than adding them one by one.
                    for tag in getattr(self, parser)(marking):
                        if tag is not None:
                            yield tag

    @staticmethod
    def _parse_simple_marking(
            marking: SimpleMarkingStructure) -> Iterator[str]:
        """Read the statement of a Simple Marking as the tag it is.

        The export writes one of these per tag that is not a TLP colour, the
        tag name whole, so the statement is a Copied Tag: added unread and
        unaltered, never through `_build_tag`, which is for the tags the
        conversion authors itself. A statement nothing survives from - absent,
        empty, whitespace alone - is dropped rather than added as an empty
        tag, as a built tag with an empty slot is.

        :param marking: the Simple Marking structure
        :return: the statement, when there is one
        """
        statement = marking.statement
        if statement is not None and statement.strip():
            yield statement

    def _parse_TLP_marking(self, marking: TLPMarkingStructure) -> Iterator[str]:
        yield self._build_tag('tlp', marking.color.lower())

    ############################################################################
    #                    OBSERVABLE OBJECTS PARSING METHODS                    #
    ############################################################################

    @staticmethod
    def _handle_address(properties: _ADDRESS_TYPING) -> tuple:
        if properties.category == 'e-mail':
            return 'email-src', properties.address_value.value, 'from'
        return "ip-src" if properties.is_source else "ip-dst", properties.address_value.value, 'ip'

    def _handle_as(self, properties: as_object.AS) -> tuple:
        attributes = tuple(
            self._fetch_attributes_with_partial_key_parsing(properties, 'as_mapping')
        )
        return attributes[0] if len(attributes) == 1 else ('asn', self._return_object_attributes(attributes), '')

    # Return type & value of an attachment attribute
    def _handle_attachment(self, properties: artifact_object.Artifact, title: str) -> tuple:
        if properties.hashes:
            return "malware-sample", f"{title}|{properties.hashes[0]}", properties.raw_artifact.value
        return self._mapping.event_types(properties._XSI_TYPE)['type'], title, properties.raw_artifact.value

    # Return type & attributes of a credential object
    def _handle_credential(self, properties: account_object.Account) -> tuple:
        attributes = []
        if properties.description:
            attributes.append(["text", properties.description.value, "text"])
        if properties.authentication:
            for authentication in properties.authentication:
                attributes.extend(
                    self._fetch_attributes_with_key_parsing(authentication, 'credential_authentication_mapping')
                )
        if properties.custom_properties:
            for prop in properties.custom_properties:
                if prop.name in self._mapping.credential_custom_types():
                    attributes.append(['text', prop.value, prop.name])
        return attributes[0] if len(attributes) == 1 else ("credential", self._return_object_attributes(attributes), "")

    # Return type & value of a custom attribute, or name & attributes of a
    # custom object: the `Custom` CybOX object is what the MISP export writes
    # an attribute or an object no other CybOX object holds into - an
    # attribute as one property named by its type, an object named by its
    # template with one property per attribute, named by its object relation.
    def _handle_custom(self, properties: custom_object.Custom) -> tuple:
        custom_properties = properties.custom_properties or ()
        if properties.custom_name is not None:
            return self._handle_custom_object(
                properties.custom_name, custom_properties,
                getattr(properties.parent, 'id_', None)
            )
        attributes = [
            (prop.name, prop.value, '') if prop.name in _MISP_types
            else ('text', prop.value, prop.name)
            for prop in custom_properties
        ]
        if not attributes:
            # A Custom object carrying no property names no attribute: the
            # caller handles the same nothing an unparsable observable yields
            return None, None, ''
        if len(attributes) == 1:
            return attributes[0]
        # Several properties on a nameless object have no object to land in:
        # they are added to the event, and one is returned as the attribute
        # the caller expects - as `_handle_whois` does with a failed object
        last_attribute = attributes.pop(-1)
        for attribute_type, attribute_value, comment in attributes:
            misp_attribute = {'comment': comment} if comment else {}
            self.misp_event.add_attribute(
                attribute_type, attribute_value, **misp_attribute
            )
        return last_attribute

    def _handle_custom_object(self, custom_name: str, custom_properties: list,
                              object_id: str) -> tuple:
        # A name that is not a plain template name would be joined into a
        # filesystem path by pymisp's template resolution: keep it out of that
        # join and convert the object as a generic, template-less one.
        name, rejected_name = _sanitise_template_name(custom_name)
        template_types = _template_attribute_types(name)
        attributes = [
            (template_types.get(prop.name, 'text'), prop.value, prop.name)
            for prop in custom_properties
        ]
        compl_data = {}
        if rejected_name is not None:
            self._invalid_template_name_warning(rejected_name, object_id)
            compl_data['rejected_name'] = rejected_name
        return name, self._return_object_attributes(attributes), compl_data

    # Return type & attributes of a dns object
    def _handle_dns(self, properties: dns_record_object.DNSRecord) -> tuple:
        relation = []
        if properties.domain_name:
            relation.append(["domain", str(properties.domain_name.value), ""])
        if properties.ip_address:
            relation.append(
                ["ip-dst", properties.ip_address.address_value.value, ""]
            )
        if relation:
            if len(relation) == 2:
                domain = relation[0][1]
                ip = relation[1][1]
                attributes = [["text", domain, "rrname"], ["text", ip, "rdata"]]
                rrtype = "AAAA" if ":" in ip else "A"
                attributes.append(["text", rrtype, "rrtype"])
                return "passive-dns", self._return_object_attributes(attributes), ""
            return relation[0]

    # Return type & value of a domain or url attribute
    def _handle_domain_or_url(self, properties: Union[domain_name_object.DomainName, uri_object.URI]) -> tuple:
        event_types = self._mapping.event_types(properties._XSI_TYPE)
        return event_types['type'], properties.value.value, event_types['relation']

    # Return type & value of an email attribute
    def _handle_email(self, properties: email_message_object.EmailMessage) -> tuple:
        if properties.header:
            header = properties.header
            attributes = list(self._fetch_attributes_with_key_parsing(header, 'email_mapping'))
            if header.to:
                for to in header.to:
                    attributes.append(["email-dst", to.address_value.value, "to"])
            if header.cc:
                for cc in header.cc:
                    attributes.append(["email-dst", cc.address_value.value, "cc"])
        else:
            attributes = []
        if properties.attachments:
            attributes.extend(self._handle_email_attachment(properties))
        return attributes[0] if len(attributes) == 1 else ("email", self._return_object_attributes(attributes), "")

    # Return type & value of an email attachment
    def _handle_email_attachment(self, properties: email_message_object.EmailMessage):
        related_objects = (
            {related.id_: related.properties for related in properties.parent.related_objects}
            if properties.parent.related_objects else {}
        )
        for attachment in (attachment.object_reference for attachment in properties.attachments):
            if attachment in related_objects:
                yield ("email-attachment", related_objects[attachment].file_name.value, "attachment")
            else:
                parent_id = self._sanitise_uuid(properties.parent.id_)
                referenced_id = self._sanitise_uuid(attachment)
                self.references[parent_id].append(
                    {'idref': referenced_id, 'relationship': 'attachment'}
                )

    # Return type & attributes of a file object
    def _handle_file(self, properties: file_object.File, is_object: bool) -> tuple:
        b_hash, b_file = False, False
        attributes = list(self._fetch_attributes_with_keys(properties, 'file_mapping'))
        if properties.byte_runs:
            attributes.append(
                (
                    'pattern-in-file', properties.byte_runs[0].byte_run_data,
                    'pattern-in-file'
                )
            )
        if properties.hashes:
            b_hash = True
            for hash_property in properties.hashes:
                attributes.append(self._handle_hashes_attribute(hash_property))
        if properties.file_name:
            value = properties.file_name.value
            if value:
                b_file = True
                attribute_type, relation = self._mapping.event_types(properties._XSI_TYPE)
                attributes.append([attribute_type, value, relation])
        if len(attributes) == 1:
            attribute = attributes[0]
            return attribute[0] if attribute[2] != "fullpath" else "filename", attribute[1], ""
        if len(attributes) == 2:
            if b_hash and b_file:
                return self._handle_filename_object(attributes, is_object)
            path, filename = self._handle_filename_path_case(attributes)
            if path and filename:
                attribute_value = f"{path}\\{filename}"
                if '\\' in filename and path == filename:
                    attribute_value = filename
                return "filename", attribute_value, ""
        return "file", self._return_object_attributes(attributes), ""

    # Determine path & filename from a complete path or filename attribute
    @staticmethod
    def _handle_filename_path_case(attributes: list) -> tuple:
        path, filename = [""] * 2
        if attributes[0][2] == 'filename' and attributes[1][2] == 'path':
            path = attributes[1][1]
            filename = attributes[0][1]
        elif attributes[0][2] == 'path' and attributes[1][2] == 'filename':
            path = attributes[0][1]
            filename = attributes[1][1]
        return path, filename

    # Return the appropriate type & value when we have 1 filename & 1 hash value
    @staticmethod
    def _handle_filename_object(attributes: list, is_object: bool) -> tuple:
        for attribute in attributes:
            attribute_type, attribute_value, _ = attribute
            if attribute_type == "filename":
                filename_value = attribute_value
            else:
                hash_type, hash_value = attribute_type, attribute_value
        value = f"{filename_value}|{hash_value}"
        if is_object:
            # file object attributes cannot be filename|hash, so it is malware-sample
            attr_type = "malware-sample"
            return attr_type, value, attr_type
        # it could be malware-sample as well, but STIX is losing this information
        return f"filename|{hash_type}", value, ""

    # Return type & value of a hash attribute
    @staticmethod
    def _handle_hashes_attribute(hash_property: Hash) -> tuple:
        hash_type = hash_property.type_.value.lower()
        try:
            hash_value = hash_property.simple_hash_value.value
        except AttributeError:
            hash_value = hash_property.fuzzy_hash_value.value
        if (hash_type == 'other' and isinstance(hash_value, str)
                and _SSDEEP_PATTERN.match(hash_value)):
            # `Other` is the type cybox gives a value of no well-known length,
            # and how MISP's own STIX 1 export wrote ssdeep: the shape names it
            hash_type = 'ssdeep'
        return hash_type, hash_value, hash_type

    # Return type & value of a hostname attribute
    def _handle_hostname(self, properties: hostname_object.Hostname) -> tuple:
        event_types = self._mapping.event_types(properties._XSI_TYPE)
        return event_types['type'], properties.hostname_value.value, event_types['relation']

    # Return type & value of a http request attribute
    @staticmethod
    def _handle_http(properties: http_session_object.HTTPSession) -> tuple:
        client_request = properties.http_request_response[0].http_client_request
        if client_request.http_request_header:
            request_header = client_request.http_request_header
            if request_header.parsed_header:
                value = request_header.parsed_header.user_agent.value
                return "user-agent", value, "user-agent"
            elif request_header.raw_header:
                value = request_header.raw_header.value
                return "http-method", value, "method"
        elif client_request.http_request_line:
            value = client_request.http_request_line.http_method.value
            return "http-method", value, "method"

    # Return type & value of a link attribute
    @staticmethod
    def _handle_link(properties: link_object.Link) -> tuple:
        return "link", properties.value.value, "link"

    # Return type & value of a mutex attribute
    def _handle_mutex(self, properties: mutex_object.Mutex) -> tuple:
        event_types = self._mapping.event_types(properties._XSI_TYPE)
        return event_types['type'], properties.name.value, event_types['relation']

    def _handle_network(self, properties: _NETWORK_PROPERTIES_TYPING, mapping: str):
        for feature, field in zip(self._mapping.network_fields(), getattr(self._mapping, mapping)()):
            address_property = getattr(properties, field)
            if address_property is None:
                continue
            for prop, attribute in self._mapping.network_reference_mapping().items():
                if getattr(address_property, prop):
                    attribute_type, key, relation = attribute
                    yield (
                        attribute_type.format(feature),
                        attrgetter(f'{prop}.{key}.value')(address_property),
                        relation.format(feature)
                    )

    # Return type & attributes of a network connection object
    def _handle_network_connection(self, properties: network_connection_object.NetworkConnection) -> tuple:
        attributes = list(self._handle_network(properties, 'network_connection_fields'))
        for feature in ('layer3_protocol', 'layer4_protocol', 'layer7_protocol'):
            if getattr(properties, feature):
                attributes.append(
                    ('text', attrgetter(f"{feature}.value")(properties), feature.replace('_', '-'))
                )
        if attributes:
            return "network-connection", self._return_object_attributes(attributes), ""

    # Return type & attributes of a network socket objet
    def _handle_network_socket(self, properties: network_socket_object.NetworkSocket) -> tuple:
        attributes = list(self._handle_network(properties, 'network_socket_fields'))
        attributes.extend(self._fetch_attributes_with_keys(properties, 'network_socket_mapping'))
        for prop in ('is_listening', 'is_blocking'):
            if getattr(properties, prop):
                attributes.append(("text", prop.split('_')[1], "state"))
        if attributes:
            return "network-socket", self._return_object_attributes(attributes), ""

    # Return type & attributes of the file defining a portable executable object
    def _handle_pe(self, properties: win_executable_file_object.WinExecutableFile) -> tuple:
        pe_object = MISPObject('pe', misp_objects_path_custom=misp_objects_path)
        for attribute in self._fetch_attributes_with_partial_key_parsing(properties, 'pe_mapping'):
            attribute_type, value, relation = attribute
            pe_object.add_attribute(relation, value, type=attribute_type)
        if getattr(properties.headers, 'file_header', None) is not None:
            header = properties.headers.file_header
            for attribute in self._fetch_attributes_with_partial_key_parsing(header, 'pe_header_mapping'):
                attribute_type, value, relation = attribute
                pe_object.add_attribute(relation, value, type=attribute_type)
        misp_object = self.misp_event.add_object(pe_object)
        if properties.sections:
            object_id = getattr(properties.parent, 'id_', None)
            for section in properties.sections:
                section_uuid = self._handle_pe_section(section, object_id)
                misp_object.add_reference(section_uuid, 'includes')
        file_type, file_value, _ = self._handle_file(properties, False)
        return file_type, file_value, {'pe_uuid': misp_object.uuid}

    def _handle_pe_section(self, section: win_executable_file_object.PESection,
                           object_id: Optional[str]) -> str:
        section_object = MISPObject('pe-section', misp_objects_path_custom=misp_objects_path)
        header_hashes = section.header_hashes
        if header_hashes is None:
            header_hashes = section.data_hashes
        if header_hashes:
            # The relation alone is what types the attribute, so a hash type
            # the template has no relation for has no type: pymisp refuses it
            template_types = _template_attribute_types('pe-section')
            for _hash in header_hashes:
                hash_type, hash_value, _ = self._handle_hashes_attribute(_hash)
                if hash_type not in template_types:
                    self._unknown_pe_section_hash_type_warning(
                        hash_type, hash_value, object_id
                    )
                    continue
                section_object.add_attribute(hash_type, hash_value)
        if section.entropy:
            section_object.add_attribute("entropy", section.entropy.value.value)
        if section.section_header:
            # Every header field is optional, and MISP's export writes the
            # header as soon as the section carries a name or a size
            section_header = section.section_header
            if section_header.name:
                section_object.add_attribute("name", section_header.name.value)
            if section_header.size_of_raw_data:
                section_object.add_attribute("size-in-bytes", section_header.size_of_raw_data.value)
        return self.misp_event.add_object(section_object).uuid

    # Return type & value of a names pipe attribute
    @staticmethod
    def _handle_pipe(properties: pipe_object.Pipe) -> tuple:
        return "named pipe", properties.name.value, ""

    # Return type & value of a port attribute
    def _handle_port(self, *args):
        properties = args[0]
        event_types = self._mapping.event_types(properties._XSI_TYPE)
        relation = event_types['relation']
        if len(args) > 1:
            observable_id = args[1]
            if "srcPort" in observable_id:
                return event_types['type'], properties.port_value.value, f"src-{relation}"
            if "dstPort" in observable_id:
                return event_types['type'], properties.port_value.value, f"dst-{relation}"
        return event_types['type'], properties.port_value.value, relation

    # Return type & attributes of a process object
    def _handle_process(self, properties: process_object.Process):
        attributes = list(
            self._fetch_attributes_with_partial_key_parsing(
                properties, 'process_mapping'
            )
        )
        if properties.child_pid_list:
            for child in properties.child_pid_list:
                attributes.append(["text", child.value, "child-pid"])
        if properties.port_list:
            for port in properties.port_list:
                attributes.append(["port", port.port_value.value, "port"])
        if properties.image_info:
            if properties.image_info.file_name:
                attributes.append(["filename", properties.image_info.file_name.value, "image"])
            if properties.image_info.command_line:
                attributes.append(["text", properties.image_info.command_line.value, "command-line"])
        if properties.network_connection_list:
            references = []
            for connection in properties.network_connection_list:
                object_name, object_attributes, _ = self._handle_network_connection(connection)
                misp_object = MISPObject(object_name, misp_objects_path_custom=misp_objects_path)
                for attribute in object_attributes:
                    misp_object.add_attribute(**attribute)
                self.misp_event.add_object(misp_object)
                references.append(misp_object.uuid)
            return "process", self._return_object_attributes(attributes), {"process_uuid": references}
        return "process", self._return_object_attributes(attributes), ""

    # Return type & value of a regkey attribute
    def _handle_regkey(self, properties: win_registry_key_object.WinRegistryKey):
        attributes = list(
            self._fetch_attributes_with_partial_key_parsing(
                properties, 'regkey_mapping'
            )
        )
        if properties.values:
            value = properties.values[0]
            attributes.extend(
                self._fetch_attributes_with_partial_key_parsing(
                    value, 'regkey_value_mapping'
                )
            )
        if len(attributes) in (2,3):
            d_regkey = {key: value for (_, value, key) in attributes}
            if 'hive' in d_regkey and 'key' in d_regkey:
                regkey = f"{d_regkey['hive']}\\{d_regkey['key']}"
                if 'data' in d_regkey:
                    return "regkey|value", f"{regkey} | {d_regkey['data']}", ""
                return "regkey", regkey, ""
        return "registry-key", self._return_object_attributes(attributes), ""

    # Parse a socket address object in order to return type & value
    # of a composite attribute ip|port or hostname|port
    def _handle_socket_address(self, properties: socket_address_object.SocketAddress) -> tuple:
        if properties.ip_address:
            type1, value1, _ = self._handle_address(properties.ip_address)
        elif properties.hostname:
            type1 = "hostname"
            value1 = properties.hostname.hostname_value.value
        if properties.port:
            return f"{type1}|port", f"{value1}|{properties.port.port_value.value}", ""
        return type1, value1, ''

    # Parse a system object to extract a mac-address attribute
    @staticmethod
    def _handle_system(properties: system_object.System) -> tuple:
        if properties.network_interface_list:
            return "mac-address", str(properties.network_interface_list[0].mac), ""

    # Parse a UNIX user account object
    def _handle_unix_user(self, properties: unix_user_account_object.UnixUserAccount) -> tuple:
        attributes = list(
            self._fetch_attributes_with_partial_key_parsing(
                properties, 'user_account_object_mapping'
            )
        )
        if properties.user_id:
            attributes.append(['text', properties.user_id.value, 'user-id'])
        if properties.group_id:
            attributes.append(['text', properties.group_id.value, 'group-id'])
        return 'user-account', self._return_object_attributes(attributes), ''

    # Parse a user account object
    def _handle_user(self, properties: user_account_object.UserAccount) -> tuple:
        attributes = tuple(
            self._fetch_attributes_with_partial_key_parsing(
                properties, 'user_account_object_mapping'
            )
        )
        return 'user-account', self._return_object_attributes(attributes), ''

    # Parse a whois object:
    # Return type & attributes of a whois object if we have the required fields
    # Otherwise create attributes and return type & value of the last attribute to avoid crashing the parent function
    def _handle_whois(self, properties: whois_object.WhoisEntry):
        attributes = list(self._fetch_attributes_with_key_parsing(properties, 'whois_mapping'))
        required_one_of = True if attributes else False
        if properties.registrants:
            registrant = properties.registrants[0]
            attributes.extend(self._fetch_attributes_with_key_parsing(registrant, 'whois_registrant_mapping'))
        if properties.creation_date:
            attributes.append(("datetime", properties.creation_date.value.strftime('%Y-%m-%d'), "creation-date"))
            required_one_of = True
        if properties.updated_date:
            attributes.append(("datetime", properties.updated_date.value.strftime('%Y-%m-%d'), "modification-date"))
        if properties.expiration_date:
            attributes.append(("datetime", properties.expiration_date.value.strftime('%Y-%m-%d'), "expiration-date"))
        if properties.nameservers:
            for nameserver in properties.nameservers:
                attributes.append(("hostname", nameserver.value.value, "nameserver"))
        if properties.remarks:
            attribute_type = "text"
            relation = "comment" if attributes else attribute_type
            attributes.append([attribute_type, properties.remarks.value, relation])
            required_one_of = True
        # Testing if we have the required attribute types for Object whois
        if required_one_of:
            # if yes, we return the object type and the attributes
            return "whois", self._return_object_attributes(attributes), ""
        # otherwise, attributes are added in the event, and one attribute is returned to not make the function crash
        if len(attributes) == 1:
            return attributes[0]
        last_attribute = attributes.pop(-1)
        for attribute in attributes:
            attribute_type, attribute_value, attribute_relation = attribute
            misp_attributes = {"comment": f"Whois {attribute_relation}"}
            self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attributes)
        return last_attribute

    # Return type & value of a windows service object
    @staticmethod
    def _handle_windows_service(properties: win_service_object.WinService) -> tuple:
        if properties.service_name:
            return "windows-service-name", properties.service_name.value, ""
        if properties.display_name:
            return "windows-service-displayname", properties.display_name.value, ""
        if properties.name:
            return "windows-service-name", properties.name.value, ""

    # Parse a windows user account object
    def _handle_windows_user(self, properties: win_user_account_object.WinUser) -> tuple:
        attributes = list(
            self._fetch_attributes_with_partial_key_parsing(
                properties, 'user_account_object_mapping'
            )
        )
        if properties.security_id:
            attributes.append(['text', properties.security_id.value, 'user-id'])
        return 'user-account', self._return_object_attributes(attributes), ''

    def _handle_x509(self, properties: x509_certificate_object.X509Certificate) -> tuple:
        attributes = list(self._handle_x509_certificate(properties))
        if properties.raw_certificate:
            raw = properties.raw_certificate.value
            try:
                relation = "raw-base64" if raw == b64encode(b64decode(raw)).strip() else "pem"
            except Exception:
                relation = "pem"
            attributes.append(["text", raw, relation])
        if properties.certificate_signature:
            signature = properties.certificate_signature
            attribute_type = f"x509-fingerprint-{signature.signature_algorithm.value.lower()}"
            attributes.append([attribute_type, signature.signature.value, attribute_type])
        return "x509", self._return_object_attributes(attributes), ""

    def _handle_x509_certificate(self, properties: x509_certificate_object.X509Certificate):
        if properties.certificate is None:
            return []
        certificate = properties.certificate
        if certificate.validity:
            validity = certificate.validity
            for prop in self._mapping.x509_datetime_types():
                if getattr(validity, prop):
                    yield ['datetime', getattr(validity, prop).value, f"validity-{prop.replace('_', '-')}"]
        if certificate.subject_public_key:
            subject_pubkey = certificate.subject_public_key
            if subject_pubkey.rsa_public_key:
                rsa_pubkey = subject_pubkey.rsa_public_key
                for prop in self._mapping.x509_pubkey_types():
                    if getattr(rsa_pubkey, prop):
                       yield ['text', getattr(rsa_pubkey, prop).value, f'pubkey-info-{prop}']
            if subject_pubkey.public_key_algorithm:
                yield ["text", subject_pubkey.public_key_algorithm.value, "pubkey-info-algorithm"]
        for prop in self._mapping.x509_certificate_types():
            if getattr(certificate, prop):
                yield ['text', getattr(certificate, prop).value, prop.replace('_', '-')]

    ############################################################################
    #                      OBJECT REFERENCES APPLICATION.                      #
    ############################################################################

    def _apply_object_references(self):
        # The related objects recorded while the package is parsed name their
        # source by the uuid of its CybOX object - the uuid of the MISP object
        # it became, which only exists once the whole package is parsed. A
        # source that became an attribute has nothing that can hold a reference
        # in MISP, so its records stay records; a target that did is referenced
        # by the attribute uuid, which MISP accepts.
        misp_objects = {
            misp_object.uuid: misp_object
            for misp_object in self.misp_event.objects
        }
        for object_uuid, references in self.references.items():
            misp_object = misp_objects.get(object_uuid)
            if misp_object is None:
                continue
            for reference in references:
                misp_object.add_reference(
                    reference['idref'], reference['relationship']
                )

    ############################################################################
    #        GALAXIES PARSING SPECIFIC METHODS USED BY BOTH SUBCLASSES.        #
    ############################################################################

    def _apply_event_galaxies(self):
        # The galaxy tags accumulated while the package is parsed only exist
        # once the whole package is - each parser applies them to its event as
        # its last parsing step, in a stable order the set cannot provide.
        for tag_name in sorted(self.galaxies):
            self.misp_event.add_tag(tag_name)

    def _refuse_empty_event(self):
        """Refuse the event a package converted nothing into.

        An event with no attribute, object or galaxy is what a document the
        parser could read nothing from yields - a MISP export parsed as
        External finds nothing at package level, a package made of a header
        has nothing below it - and a caller told the conversion succeeded
        writes it as an imported event holding nothing. Raised as the error
        MISP core already reads as `contains nothing to import`, so that the
        consumers driving the parser themselves refuse it as the entry
        functions do. The errors recorded are counted in the message: a
        document carrying nothing and one carrying only what the parser could
        not read are refused alike, and the count is what tells the reader of
        the message which one they hold - the errors recorded on the instance,
        which under Parser Reuse are the ones of every document it converted.

        :raises MissingSTIXContentError: if nothing converted
        """
        if self.misp_event.attributes or self.misp_event.objects or self.galaxies:
            return
        message = (
            f'The STIX {self.stix_version} package converted to no MISP '
            'attribute, object or galaxy'
        )
        errors = sum(len(recorded) for recorded in self.errors.values())
        if errors:
            message = f"{message} - {errors} error{'s' if errors > 1 else ''} recorded"
        raise MissingSTIXContentError(f'{message}.')

    @staticmethod
    def _get_galaxy_name(stix_object: _STIX_OBJECT_TYPING,
                         feature: str) -> Union[str, list, None]:
        if getattr(stix_object, feature, None) is not None:
            return getattr(stix_object, feature)
        for feature in ('name', 'names'):
            if getattr(stix_object, feature, None) is not None:
                return [value.value for value in getattr(stix_object, feature)]

    def _parse_galaxy(self, stix_object: _STIX_OBJECT_TYPING,
                      feature: str, construct: str):
        names = self._get_galaxy_name(stix_object, feature)
        if names:
            if isinstance(names, list):
                for name in names:
                    yield from self._resolve_galaxy(name, construct)
            else:
                yield from self._resolve_galaxy(names, construct)

    def _resolve_galaxy(self, galaxy_name: str, construct: str) -> list:
        tag_name = self._build_tag(
            'misp-galaxy', self._mapping.galaxy_types_mapping(construct),
            galaxy_name
        )
        return [tag_name] if tag_name is not None else []

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _extract_uuid(object_id: str) -> str:
        return '-'.join(object_id.split('-')[1:])

    def _fetch_attributes_with_keys(self, properties: _SIMPLE_PROPERTIES_TYPING, mapping: str):
        for field, attribute in getattr(self._mapping, mapping)().items():
            if getattr(properties, field):
                attribute_type, feature, relation = attribute
                yield (attribute_type, attrgetter(feature)(properties), relation)

    def _fetch_attributes_with_key_parsing(self, properties: _PROPERTIES_TYPING, mapping: str):
        for field, attribute in getattr(self._mapping, mapping)().items():
            if getattr(properties, field):
                attribute_type, feature, relation = attribute
                yield (attribute_type, attrgetter(f'{field}.{feature}')(properties), relation)

    def _fetch_attributes_with_partial_key_parsing(self, properties: _PARTIAL_PROPERTIES_TYPING, mapping: str):
        for field, attribute in getattr(self._mapping, mapping)().items():
            if getattr(properties, field):
                attribute_type, relation = attribute
                yield (attribute_type, getattr(properties, field).value, relation)

    @classmethod
    def _read_object_comment(
            cls, name: Optional[str], description,
            title: Optional[str]) -> Optional[str]:
        """Read the comment a MISP object carried, guarded against the
        description its own template gives every object made from it.

        :param name: the object template name, None when the shape names none
        :param description: the STIX description field, or None
        :param title: the Record Title, where the shape carries one
        :return: the comment, None when the object carried none
        """
        return cls._read_comment(description, title, _template_description(name))

    @staticmethod
    def _read_comment(
            description, *written_without_a_comment: Optional[str]
    ) -> Optional[str]:
        """Read the comment a MISP record carried off a STIX description.

        The export writes the comment as the description, and on two shapes
        writes something else there when the record has no comment: the
        Record Title on an Indicator, the object template's own description
        on the Indicator a MISP object was exported as. Those stand in for
        `no comment`, so a description equal to one of them reads as none -
        at the cost of losing a comment whose author typed exactly that.

        :param description: the STIX description field, or None - a
            structured text, or the plain string a package built in memory
            and handed to `load_stix_package` carries
        :param written_without_a_comment: what the export writes there when
            the record has no comment, if anything
        :return: the comment, None when the record carried none
        """
        value = getattr(description, 'value', description)
        if not isinstance(value, str) or not value:
            return None
        return None if value in written_without_a_comment else value

    @staticmethod
    def _return_object_attributes(attributes: Union[list, tuple]) -> tuple:
        return tuple(
            dict(zip(('type', 'value', 'object_relation'), attribute))
            for attribute in attributes
        )

    @staticmethod
    def _record_rejected_template_name(misp_object: MISPObject, name: str):
        # Nothing is silently dropped: the name the object cannot carry is
        # kept as data, appended to whatever comment it already has.
        note = _rejected_name_note(name)
        comment = getattr(misp_object, 'comment', None)
        misp_object.comment = f'{comment}\n{note}' if comment else note

    def _set_distribution(self):
        # The event JSON has to carry the distribution the caller asked for:
        # MISP saves an event without one with the column default, org-only
        self.misp_event.distribution = self.distribution
        if self.distribution == 4 and self.sharing_group_id is not None:
            self.misp_event.sharing_group_id = self.sharing_group_id

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    @staticmethod
    def _object_origin(object_id: Optional[str]) -> str:
        return f' in the object with id {object_id}' if object_id else ''

    def _invalid_template_name_warning(
            self, rejected_name: str, object_id: Optional[str] = None):
        self._add_warning(
            f'Invalid MISP object template name {rejected_name!r}'
            f'{self._object_origin(object_id)}: '
            f'converted as a {_UNKNOWN_TEMPLATE_NAME} object.'
        )

    def _object_markings_warning(self):
        # One per converted document however many objects hit it: a MISP
        # object takes no tag, and the markings the export wrote hold the
        # tags of every attribute it held merged into one set, so there is
        # neither a field to write them to nor a way to tell them apart.
        self._add_warning(
            'MISP objects carry no tag: the markings written on the STIX '
            'objects a MISP object was exported as are not read back.'
        )

    def _unknown_pe_section_hash_type_warning(
            self, hash_type: str, hash_value: str, object_id: Optional[str]):
        self._add_warning(
            f'Unknown PE section hash type {hash_type!r}'
            f'{self._object_origin(object_id)}: {hash_value} not converted.'
        )

    def _unnamed_object_error(self, object_uuid: Optional[str]):
        origin = f' with id {object_uuid}' if object_uuid else ''
        self._add_error(
            f'Unable to convert the Observable{origin}: '
            'nothing to name a MISP object with'
        )

    def _stix_object_type_error(self, xsi_type: str, object_id: str):
        self._add_error(f"Unknown Observable type within STIX object with id {object_id}: {xsi_type}")