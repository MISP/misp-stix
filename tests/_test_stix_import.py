#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from collections import defaultdict
from misp_stix_converter import InternalSTIX2toMISPParser
from ._test_stix import TestSTIX2


class TestSTIX2Import(TestSTIX2):
    def _check_attribute_labels(self, attribute, labels):
        if len(labels) == 3:
            type_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{attribute.to_ids}"')
        else:
            type_label, category_label = labels
        self.assertEqual(type_label, f'misp:type="{attribute.type}"')
        self.assertEqual(category_label, f'misp:category="{attribute.category}"')

    def _check_misp_event_features(self, event, report, published=False):
        self.assertEqual(event.uuid, report.id.split('--')[1])
        self.assertEqual(event.info, report.name)
        self._assert_multiple_equal(
            event.timestamp,
            self._timestamp_from_datetime(report.created),
            self._timestamp_from_datetime(report.modified)
        )
        self.assertEqual(event.published, published)
        return (*event.objects, *event.attributes)

    def _check_object_labels(self, misp_object, labels, to_ids=None):
        if to_ids is not None:
            name_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{to_ids}"')
        else:
            name_label, category_label = labels
        self.assertEqual(name_label, f'misp:name="{misp_object.name}"')
        self.assertEqual(
            category_label,
            f'misp:meta-category="{getattr(misp_object, "meta-category")}"'
        )

    @staticmethod
    def _get_data_value(data):
        return b64encode(data.getvalue()).decode()

    @staticmethod
    def _get_pattern_value(pattern):
        return pattern.split(' = ')[1].strip("'")

    @staticmethod
    def _timestamp_from_datetime(datetime_value):
        return int(datetime_value.timestamp())


class TestInternalSTIX2Import(TestSTIX2Import):
    def setUp(self):
        self.parser = InternalSTIX2toMISPParser(False)

    ################################################################################
    #                      MISP ATTRIBUTES CHECKING FUNCTIONS                      #
    ################################################################################

    def _check_campaign_name_attribute(self, attribute, campaign):
        self.assertEqual(attribute.uuid, campaign.id.split('--')[1])
        self.assertEqual(attribute.type, 'campaign-name')
        self._assert_multiple_equal(
            attribute.timestamp,
            campaign.created,
            campaign.modified
        )
        self._check_attribute_labels(attribute, campaign.labels)
        self.assertEqual(attribute.value, campaign.name)

    def _check_indicator_attribute(self, attribute, indicator):
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._assert_multiple_equal(
            attribute.timestamp,
            indicator.created,
            indicator.modified
        )
        self._check_attribute_labels(attribute, indicator.labels)
        return indicator.pattern

    def _check_indicator_object(self, misp_object, indicator):
        self.assertEqual(misp_object.uuid, indicator.id.split('--')[1])
        self.assertEqual(
            misp_object.timestamp,
            self._timestamp_from_datetime(indicator.modified)
        )
        self._check_object_labels(misp_object, indicator.labels, True)
        return indicator.pattern

    def _check_vulnerability_attribute(self, attribute, vulnerability):
        self.assertEqual(attribute.uuid, vulnerability.id.split('--')[1])
        self.assertEqual(attribute.type, vulnerability.type)
        self._assert_multiple_equal(
            attribute.timestamp,
            vulnerability.created,
            vulnerability.modified
        )
        self._check_attribute_labels(attribute, vulnerability.labels)
        self._assert_multiple_equal(
            attribute.value,
            vulnerability.name,
            vulnerability.external_references[0].external_id
        )

    ################################################################################
    #                       MISP OBJECTS CHECKING FUNCTIONS.                       #
    ################################################################################

    def _check_asn_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        number, name, *subnets = pattern[1:-1].split(' AND ')
        asn, description, *subnets_announced = attributes
        self.assertEqual(asn.type, 'AS')
        self.assertEqual(asn.object_relation, 'asn')
        self.assertEqual(asn.value, f'AS{self._get_pattern_value(number)}')
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, self._get_pattern_value(name))
        for subnet_announced, subnet in zip(subnets_announced, subnets):
            self.assertEqual(subnet_announced.type, 'ip-src')
            self.assertEqual(subnet_announced.object_relation, 'subnet-announced')
            self.assertEqual(subnet_announced.value, self._get_pattern_value(subnet))

    def _check_asn_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 4)
        asn, description, *subnets_announced = attributes
        self.assertEqual(asn.type, 'AS')
        self.assertEqual(asn.object_relation, 'asn')
        self.assertEqual(asn.value, f'AS{observable.number}')
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, observable.name)
        for attribute, subnet in zip(subnets_announced, observable.x_misp_subnet_announced):
            self.assertEqual(attribute.type, 'ip-src')
            self.assertEqual(attribute.object_relation, 'subnet-announced')
            self.assertEqual(attribute.value, subnet)

    def _check_attack_pattern_object(self, misp_object, attack_pattern):
        self.assertEqual(misp_object.uuid, attack_pattern.id.split('--')[1])
        self.assertEqual(misp_object.name, attack_pattern.type)
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(attack_pattern.created),
            self._timestamp_from_datetime(attack_pattern.modified)
        )
        self._check_object_labels(misp_object, attack_pattern.labels, False)
        summary, name, prerequisites, weakness1, weakness2, solution, capec_id = misp_object.attributes
        self.assertEqual(summary.value, attack_pattern.description)
        self.assertEqual(name.value, attack_pattern.name)
        self.assertEqual(prerequisites.value, attack_pattern.x_misp_prerequisites)
        self.assertEqual(weakness1.value, attack_pattern.x_misp_related_weakness[0])
        self.assertEqual(weakness2.value, attack_pattern.x_misp_related_weakness[1])
        self.assertEqual(solution.value, attack_pattern.x_misp_solutions)
        self.assertEqual(
            f"CAPEC-{capec_id.value}",
            attack_pattern.external_references[0].external_id
        )

    def _check_course_of_action_object(self, misp_object, course_of_action):
        self.assertEqual(misp_object.uuid, course_of_action.id.split('--')[1])
        self.assertEqual(misp_object.name, course_of_action.type)
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(course_of_action.created),
            self._timestamp_from_datetime(course_of_action.modified)
        )
        self._check_object_labels(misp_object, course_of_action.labels, False)
        name, description, *attributes = misp_object.attributes
        self.assertEqual(name.value, course_of_action.name)
        self.assertEqual(description.value, course_of_action.description)
        for attribute in attributes:
            self.assertEqual(
                attribute.value,
                getattr(course_of_action, f"x_misp_{attribute.object_relation}")
            )

    def _check_cpe_asset_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 6)
        cpe, language, product, vendor, version, description = attributes
        cpe_pattern, language_pattern, name, vendor_pattern, version_pattern, description_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(cpe.type, 'cpe')
        self.assertEqual(cpe.object_relation, 'cpe')
        self.assertEqual(cpe.value, self._get_pattern_value(cpe_pattern))
        self.assertEqual(language.type, 'text')
        self.assertEqual(language.object_relation, 'language')
        self.assertEqual(language.value, self._get_pattern_value(language_pattern))
        self.assertEqual(product.type, 'text')
        self.assertEqual(product.object_relation, 'product')
        self.assertEqual(product.value, self._get_pattern_value(name))
        self.assertEqual(vendor.type, 'text')
        self.assertEqual(vendor.object_relation, 'vendor')
        self.assertEqual(vendor.value, self._get_pattern_value(vendor_pattern))
        self.assertEqual(version.type, 'text')
        self.assertEqual(version.object_relation, 'version')
        self.assertEqual(version.value, self._get_pattern_value(version_pattern))
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, self._get_pattern_value(description_pattern))

    def _check_cpe_asset_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 6)
        cpe, language, product, vendor, version, description = attributes
        self.assertEqual(cpe.type, 'cpe')
        self.assertEqual(cpe.object_relation, 'cpe')
        self.assertEqual(cpe.value, observable.cpe)
        self.assertEqual(language.type, 'text')
        self.assertEqual(language.object_relation, 'language')
        self.assertEqual(language.value, observable.languages[0])
        self.assertEqual(product.type, 'text')
        self.assertEqual(product.object_relation, 'product')
        self.assertEqual(product.value, observable.name)
        self.assertEqual(vendor.type, 'text')
        self.assertEqual(vendor.object_relation, 'vendor')
        self.assertEqual(vendor.value, observable.vendor)
        self.assertEqual(version.type, 'text')
        self.assertEqual(version.object_relation, 'version')
        self.assertEqual(version.value, observable.version)
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, observable.x_misp_description)

    def _check_credential_indicator_object(self, attributes, pattern_list):
        self.assertEqual(len(attributes), 7)
        username, password, *attributes = attributes
        user_id, credential, *patterns = pattern_list
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, self._get_pattern_value(user_id))
        self.assertEqual(password.type, 'text')
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, self._get_pattern_value(credential))
        for attribute, pattern in zip(attributes, patterns):
            self.assertEqual(attribute.type, 'text')
            identifier, value = pattern.split (' = ')
            self.assertEqual(attribute.object_relation, identifier.split(':')[1][7:])
            self.assertEqual(attribute.value, value.strip("'"))

    def _check_credential_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 7)
        username, password, *attributes = attributes
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, observable.user_id)
        features = ('format', 'notification', 'origin', 'text', 'type')
        for attribute, feature in zip(attributes, features):
            self.assertEqual(attribute.type, 'text')
            self.assertEqual(
                attribute.object_relation,
                feature
            )
            self.assertEqual(
                attribute.value,
                getattr(observable, f'x_misp_{feature}')
            )
        return password

    def _check_domain_ip_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        domain_pattern, hostname_pattern, resolves_to_ref, port_pattern = pattern[1:-1].split(' AND ')
        domain, hostname, ip, port = attributes
        self.assertEqual(domain.type, 'domain')
        self.assertEqual(domain.object_relation, 'domain')
        self.assertEqual(domain.value, self._get_pattern_value(domain_pattern))
        self.assertEqual(hostname.type, 'hostname')
        self.assertEqual(hostname.object_relation, 'hostname')
        self.assertEqual(hostname.value, self._get_pattern_value(hostname_pattern))
        self.assertEqual(ip.type, 'ip-dst')
        self.assertEqual(ip.object_relation, 'ip')
        self.assertEqual(ip.value, self._get_pattern_value(resolves_to_ref))
        self.assertEqual(port.type, 'port')
        self.assertEqual(port.object_relation, 'port')
        self.assertEqual(port.value, self._get_pattern_value(port_pattern))

    def _check_email_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 18)
        _to, to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn, _from, from_dn, message_id, reply_to, subject, x_mailer, user_agent, boundary, *attachments = attributes
        self.assertEqual(_to.type, 'email-dst')
        self.assertEqual(_to.object_relation, 'to')
        self.assertEqual(_to.value, pattern['to_refs[0].value'])
        self.assertEqual(to_dn.type, 'email-dst-display-name')
        self.assertEqual(to_dn.object_relation, 'to-display-name')
        self.assertEqual(to_dn.value, pattern['to_refs[0].display_name'])
        self.assertEqual(cc1.type, 'email-dst')
        self.assertEqual(cc1.object_relation, 'cc')
        self.assertEqual(cc1.value, pattern['cc_refs[0].value'])
        self.assertEqual(cc1_dn.type, 'email-dst-display-name')
        self.assertEqual(cc1_dn.object_relation, 'cc-display-name')
        self.assertEqual(cc1_dn.value, pattern['cc_refs[0].display_name'])
        self.assertEqual(cc2.type, 'email-dst')
        self.assertEqual(cc2.object_relation, 'cc')
        self.assertEqual(cc2.value, pattern['cc_refs[1].value'])
        self.assertEqual(cc2_dn.type, 'email-dst-display-name')
        self.assertEqual(cc2_dn.object_relation, 'cc-display-name')
        self.assertEqual(cc2_dn.value, pattern['cc_refs[1].display_name'])
        self.assertEqual(bcc.type, 'email-dst')
        self.assertEqual(bcc.object_relation, 'bcc')
        self.assertEqual(bcc.value, pattern['bcc_refs[0].value'])
        self.assertEqual(bcc_dn.type, 'email-dst-display-name')
        self.assertEqual(bcc_dn.object_relation, 'bcc-display-name')
        self.assertEqual(bcc_dn.value, pattern['bcc_refs[0].display_name'])
        self.assertEqual(_from.type, 'email-src')
        self.assertEqual(_from.object_relation, 'from')
        self.assertEqual(_from.value, pattern['from_ref.value'])
        self.assertEqual(from_dn.type, 'email-src-display-name')
        self.assertEqual(from_dn.object_relation, 'from-display-name')
        self.assertEqual(from_dn.value, pattern['from_ref.display_name'])
        self.assertEqual(message_id.type, 'email-message-id')
        self.assertEqual(message_id.object_relation, 'message-id')
        self.assertEqual(message_id.value, pattern['message_id' if 'message_id' in pattern else 'x_misp_message_id'])
        self.assertEqual(reply_to.type, 'email-reply-to')
        self.assertEqual(reply_to.object_relation, 'reply-to')
        self.assertEqual(reply_to.value, pattern['additional_header_fields.reply_to'])
        self.assertEqual(subject.type, 'email-subject')
        self.assertEqual(subject.object_relation, 'subject')
        self.assertEqual(subject.value, pattern['subject'])
        self.assertEqual(x_mailer.type, 'email-x-mailer')
        self.assertEqual(x_mailer.object_relation, 'x-mailer')
        self.assertEqual(x_mailer.value, pattern['additional_header_fields.x_mailer'])
        self.assertEqual(user_agent.type, 'text')
        self.assertEqual(user_agent.object_relation, 'user-agent')
        self.assertEqual(user_agent.value, pattern['x_misp_user_agent'])
        self.assertEqual(boundary.type, 'email-mime-boundary')
        self.assertEqual(boundary.object_relation, 'mime-boundary')
        self.assertEqual(boundary.value, pattern['x_misp_mime_boundary'])
        for index, attribute in enumerate(attachments):
            self.assertEqual(attribute.type, 'attachment')
            self.assertEqual(attribute.object_relation, pattern[f'body_multipart[{index}].content_disposition'])
            self.assertEqual(attribute.value, pattern[f'body_multipart[{index}].body_raw_ref.name'])

    def _check_email_observable_object(self, attributes, observables):
        self.assertEqual(len(attributes), 18)
        _from, _from_dn, _to, _to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn, subject, message_id, boundary, user_agent, reply_to, x_mailer, *attachments = attributes
        message, addr1, addr2, addr3, addr4, addr5, file1, file2 = observables.values()
        self.assertEqual(_from.type, 'email-src')
        self.assertEqual(_from.object_relation, 'from')
        self.assertEqual(_from.value, addr1.value)
        self.assertEqual(_from_dn.type, 'email-src-display-name')
        self.assertEqual(_from_dn.object_relation, 'from-display-name')
        self.assertEqual(_from_dn.value, addr1.display_name)
        self.assertEqual(_to.type, 'email-dst')
        self.assertEqual(_to.object_relation, 'to')
        self.assertEqual(_to.value, addr2.value)
        self.assertEqual(_to_dn.type, 'email-dst-display-name')
        self.assertEqual(_to_dn.object_relation, 'to-display-name')
        self.assertEqual(_to_dn.value, addr2.display_name)
        self.assertEqual(cc1.type, 'email-dst')
        self.assertEqual(cc1.object_relation, 'cc')
        self.assertEqual(cc1.value, addr3.value)
        self.assertEqual(cc1_dn.type, 'email-dst-display-name')
        self.assertEqual(cc1_dn.object_relation, 'cc-display-name')
        self.assertEqual(cc1_dn.value, addr3.display_name)
        self.assertEqual(cc2.type, 'email-dst')
        self.assertEqual(cc2.object_relation, 'cc')
        self.assertEqual(cc2.value, addr4.value)
        self.assertEqual(cc2_dn.type, 'email-dst-display-name')
        self.assertEqual(cc2_dn.object_relation, 'cc-display-name')
        self.assertEqual(cc2_dn.value, addr4.display_name)
        self.assertEqual(bcc.type, 'email-dst')
        self.assertEqual(bcc.object_relation, 'bcc')
        self.assertEqual(bcc.value, addr5.value)
        self.assertEqual(bcc_dn.type, 'email-dst-display-name')
        self.assertEqual(bcc_dn.object_relation, 'bcc-display-name')
        self.assertEqual(bcc_dn.value, addr5.display_name)
        self.assertEqual(subject.type, 'email-subject')
        self.assertEqual(subject.object_relation, 'subject')
        self.assertEqual(subject.value, message.subject)
        self.assertEqual(boundary.type, 'email-mime-boundary')
        self.assertEqual(boundary.object_relation, 'mime-boundary')
        self.assertEqual(boundary.value, message.x_misp_mime_boundary)
        self.assertEqual(user_agent.type, 'text')
        self.assertEqual(user_agent.object_relation, 'user-agent')
        self.assertEqual(user_agent.value, message.x_misp_user_agent)
        additional_header = message.additional_header_fields
        self.assertEqual(reply_to.type, 'email-reply-to')
        self.assertEqual(reply_to.object_relation, 'reply-to')
        self.assertEqual(reply_to.value, additional_header['Reply-To'])
        self.assertEqual(x_mailer.type, 'email-x-mailer')
        self.assertEqual(x_mailer.object_relation, 'x-mailer')
        self.assertEqual(x_mailer.value, additional_header['X-Mailer'])
        for attribute, body, observable in zip(attachments, message.body_multipart, (file1, file2)):
            self.assertEqual(attribute.type, 'email-attachment')
            self.assertEqual(
                attribute.object_relation,
                body['content_disposition'].split(';')[0]
            )
            self.assertEqual(attribute.value, observable.name)
        return message_id

    def _check_employee_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'employee')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, employee_type, email = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual(
            identity.contact_information,
            f"{email.object_relation}: {email.value}"
        )
        return employee_type

    def _check_facebook_account_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        user_id, account_login, link_pattern, *avatar_pattern = pattern[1:-1].split(' AND ')[1:]
        account_id, account_name, link, avatar = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, self._get_pattern_value(user_id))
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, self._get_pattern_value(account_login))
        self.assertEqual(link.type, 'link')
        self.assertEqual(link.object_relation, 'link')
        self.assertEqual(link.value, self._get_pattern_value(link_pattern))
        self.assertEqual(avatar.type, 'attachment')
        self.assertEqual(avatar.object_relation, 'user-avatar')
        avatar_data, avatar_value = avatar_pattern
        self.assertEqual(avatar.value, self._get_pattern_value(avatar_value))
        self.assertEqual(
            self._get_data_value(avatar.data),
            self._get_pattern_value(avatar_data)
        )

    def _check_facebook_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 4)
        account_id, account_name, link, avatar = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, observable.user_id)
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, observable.account_login)
        self.assertEqual(link.type, 'link')
        self.assertEqual(link.object_relation, 'link')
        self.assertEqual(link.value, observable.x_misp_link)
        self.assertEqual(avatar.type, 'attachment')
        self.assertEqual(avatar.object_relation, 'user-avatar')
        self.assertEqual(avatar.value, observable.x_misp_user_avatar['value'])
        self.assertEqual(
            self._get_data_value(avatar.data),
            observable.x_misp_user_avatar['data']
        )

    def _check_file_and_pe_observable_object(self, file_attributes, pe_attributes, section_attributes, observable):
        self.assertEqual(len(file_attributes), 6)
        md5, sha1, sha256, filename, size, entropy = file_attributes
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, observable.hashes['MD5'])
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, observable.hashes['SHA-1'])
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, observable.hashes['SHA-256'])
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, observable.name)
        self.assertEqual(size.type, 'size-in-bytes')
        self.assertEqual(size.object_relation, 'size-in-bytes')
        self.assertEqual(size.value, observable.size)
        self.assertEqual(entropy.type, 'float')
        self.assertEqual(entropy.object_relation, 'entropy')
        self.assertEqual(entropy.value, observable.x_misp_entropy)
        self.assertEqual(len(pe_attributes), 15)
        entrypoint, imphash, number, pe_type, company_name, compilation, description, file_version, impfuzzy, internal, lang_id, legal, original, name, product_version = pe_attributes
        extension = observable.extensions['windows-pebinary-ext']
        self.assertEqual(entrypoint.type, 'text')
        self.assertEqual(entrypoint.object_relation, 'entrypoint-address')
        self.assertEqual(entrypoint.value, extension.optional_header['address_of_entry_point'])
        self.assertEqual(imphash.type, 'imphash')
        self.assertEqual(imphash.object_relation, 'imphash')
        self.assertEqual(imphash.value, extension.imphash)
        self.assertEqual(number.type, 'counter')
        self.assertEqual(number.object_relation, 'number-sections')
        self.assertEqual(number.value, extension.number_of_sections)
        self.assertEqual(pe_type.type, 'text')
        self.assertEqual(pe_type.object_relation, 'type')
        self.assertEqual(pe_type.value, extension.pe_type)
        self.assertEqual(company_name.type, 'text')
        self.assertEqual(company_name.object_relation, 'company-name')
        self.assertEqual(company_name.value, extension.x_misp_company_name)
        self.assertEqual(compilation.type, 'datetime')
        self.assertEqual(compilation.object_relation, 'compilation-timestamp')
        self.assertEqual(
            self._datetime_to_str(compilation.value),
            extension.x_misp_compilation_timestamp
        )
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'file-description')
        self.assertEqual(description.value, extension.x_misp_file_description)
        self.assertEqual(file_version.type, 'text')
        self.assertEqual(file_version.object_relation, 'file-version')
        self.assertEqual(file_version.value, extension.x_misp_file_version)
        self.assertEqual(impfuzzy.type, 'impfuzzy')
        self.assertEqual(impfuzzy.object_relation, 'impfuzzy')
        self.assertEqual(impfuzzy.value, extension.x_misp_impfuzzy)
        self.assertEqual(internal.type, 'filename')
        self.assertEqual(internal.object_relation, 'internal-filename')
        self.assertEqual(internal.value, extension.x_misp_internal_filename)
        self.assertEqual(lang_id.type, 'text')
        self.assertEqual(lang_id.object_relation, 'lang-id')
        self.assertEqual(lang_id.value, extension.x_misp_lang_id)
        self.assertEqual(legal.type, 'text')
        self.assertEqual(legal.object_relation, 'legal-copyright')
        self.assertEqual(legal.value, extension.x_misp_legal_copyright)
        self.assertEqual(original.type, 'filename')
        self.assertEqual(original.object_relation, 'original-filename')
        self.assertEqual(original.value, extension.x_misp_original_filename)
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'product-name')
        self.assertEqual(name.value, extension.x_misp_product_name)
        self.assertEqual(product_version.type, 'text')
        self.assertEqual(product_version.object_relation, 'product-version')
        self.assertEqual(product_version.value, extension.x_misp_product_version)
        self.assertEqual(len(section_attributes), 8)
        entropy, name, size, md5, sha1, sha256, sha512, ssdeep = section_attributes
        section = extension.sections[0]
        self.assertEqual(entropy.type, 'float')
        self.assertEqual(entropy.object_relation, 'entropy')
        self.assertEqual(entropy.value, section.entropy)
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, section.name)
        self.assertEqual(size.type, 'size-in-bytes')
        self.assertEqual(size.object_relation, 'size-in-bytes')
        self.assertEqual(size.value, section.size)
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, section.hashes['MD5'])
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, section.hashes['SHA-1'])
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, section.hashes['SHA-256'])
        self.assertEqual(sha512.type, 'sha512')
        self.assertEqual(sha512.object_relation, 'sha512')
        self.assertEqual(sha512.value, section.hashes['SHA-512'])
        self.assertEqual(ssdeep.type, 'ssdeep')
        self.assertEqual(ssdeep.object_relation, 'ssdeep')
        feature = 'SSDEEP' if 'SSDEEP' in section.hashes else 'ssdeep'
        self.assertEqual(ssdeep.value, section.hashes[feature])

    def _check_file_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 9)
        md5, sha1, sha256, filename, encoding, size_in_bytes, _path, malware_sample, attachment = attributes
        MD5, SHA1, SHA256, name, name_enc, size, path_ref, ms_payload, ms_filename, ms_md5, a_payload, a_filename = pattern
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, self._get_pattern_value(MD5))
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, self._get_pattern_value(SHA1))
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, self._get_pattern_value(SHA256))
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, self._get_pattern_value(name))
        self.assertEqual(encoding.type, 'text')
        self.assertEqual(encoding.object_relation, 'file-encoding')
        self.assertEqual(encoding.value, self._get_pattern_value(name_enc))
        self.assertEqual(size_in_bytes.type, 'size-in-bytes')
        self.assertEqual(size_in_bytes.object_relation, 'size-in-bytes')
        self.assertEqual(size_in_bytes.value, self._get_pattern_value(size))
        self.assertEqual(_path.type, 'text')
        self.assertEqual(_path.object_relation, 'path')
        self.assertEqual(_path.value, self._get_pattern_value(path_ref))
        self.assertEqual(malware_sample.type, 'malware-sample')
        self.assertEqual(malware_sample.object_relation, 'malware-sample')
        filename_value = self._get_pattern_value(ms_filename)
        md5_value = self._get_pattern_value(ms_md5)
        self.assertEqual(malware_sample.value, f'{filename_value}|{md5_value}')
        self.assertEqual(
            self._get_data_value(malware_sample.data),
            self._get_pattern_value(ms_payload)
        )
        self.assertEqual(attachment.type, 'attachment')
        self.assertEqual(attachment.object_relation, 'attachment')
        self.assertEqual(attachment.value, self._get_pattern_value(a_filename)[:-2])
        self.assertEqual(
            self._get_data_value(attachment.data),
            self._get_pattern_value(a_payload)
        )

    def _check_file_observable_object(self, attributes, observables):
        self.assertEqual(len(attributes), 9)
        md5, sha1, sha256, filename, encoding, size_in_bytes, attachment, _path, malware_sample = attributes
        file_object, directory, artifact = observables.values()
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, file_object.hashes['MD5'])
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, file_object.hashes['SHA-1'])
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, file_object.hashes['SHA-256'])
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, file_object.name)
        self.assertEqual(encoding.type, 'text')
        self.assertEqual(encoding.object_relation, 'file-encoding')
        self.assertEqual(encoding.value, file_object.name_enc)
        self.assertEqual(size_in_bytes.type, 'size-in-bytes')
        self.assertEqual(size_in_bytes.object_relation, 'size-in-bytes')
        self.assertEqual(size_in_bytes.value, file_object.size)
        self.assertEqual(attachment.type, 'attachment')
        self.assertEqual(attachment.object_relation, 'attachment')
        self.assertEqual(attachment.value, file_object.x_misp_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            file_object.x_misp_attachment['data']
        )
        self.assertEqual(_path.type, 'text')
        self.assertEqual(_path.object_relation, 'path')
        self.assertEqual(_path.value, directory.path)
        self.assertEqual(malware_sample.type, 'malware-sample')
        self.assertEqual(malware_sample.object_relation, 'malware-sample')
        self.assertEqual(
            malware_sample.value,
            f"{artifact.x_misp_filename}|{artifact.hashes['MD5']}"
        )
        self.assertEqual(self._get_data_value(malware_sample.data), artifact.payload_bin)

    def _check_github_user_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 5)
        user_id, display_name, account_login, organisation, *image_pattern = pattern[1:-1].split(' AND ')[1:]
        id_attribute, fullname, username, organisation_attribute, profile_image = attributes
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, self._get_pattern_value(user_id))
        self.assertEqual(fullname.type, 'text')
        self.assertEqual(fullname.object_relation, 'user-fullname')
        self.assertEqual(fullname.value, self._get_pattern_value(display_name))
        self.assertEqual(username.type, 'github-username')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, self._get_pattern_value(account_login))
        self.assertEqual(organisation_attribute.type, 'github-organisation')
        self.assertEqual(organisation_attribute.object_relation, 'organisation')
        self.assertEqual(organisation_attribute.value, self._get_pattern_value(organisation))
        self.assertEqual(profile_image.type, 'attachment')
        self.assertEqual(profile_image.object_relation, 'profile-image')
        image_data, image_value = image_pattern
        self.assertEqual(profile_image.value, self._get_pattern_value(image_value))
        self.assertEqual(
            self._get_data_value(profile_image.data),
            self._get_pattern_value(image_data)
        )

    def _check_github_user_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 5)
        id_attribute, username, fullname, organisation_attribute, profile_image = attributes
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, observable.user_id)
        self.assertEqual(username.type, 'github-username')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, observable.account_login)
        self.assertEqual(fullname.type, 'text')
        self.assertEqual(fullname.object_relation, 'user-fullname')
        self.assertEqual(fullname.value, observable.display_name)
        self.assertEqual(organisation_attribute.type, 'github-organisation')
        self.assertEqual(organisation_attribute.object_relation, 'organisation')
        self.assertEqual(organisation_attribute.value, observable.x_misp_organisation)
        self.assertEqual(profile_image.type, 'attachment')
        self.assertEqual(profile_image.object_relation, 'profile-image')
        self.assertEqual(profile_image.value, observable.x_misp_profile_image['value'])
        self.assertEqual(
            self._get_data_value(profile_image.data),
            observable.x_misp_profile_image['data']
        )

    def _check_gitlab_user_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 3)
        user_id, display_name, account_login = pattern[1:-1].split(' AND ')[1:]
        id_attribute, name, username = attributes
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, self._get_pattern_value(user_id))
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, self._get_pattern_value(display_name))
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, self._get_pattern_value(account_login))

    def _check_gitlab_user_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 3)
        user_id, name, username = attributes
        self.assertEqual(user_id.type, 'text')
        self.assertEqual(user_id.object_relation, 'id')
        self.assertEqual(user_id.value, observable.user_id)
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, observable.display_name)
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, observable.account_login)

    def _check_image_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        name, payload_bin, _, x_misp_filename, x_misp_url, x_misp_image_text = pattern[1:-1].split(' AND ')
        filename, url, image_text, attachment = attributes
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, self._get_pattern_value(name))
        self.assertEqual(url.type, 'url')
        self.assertEqual(url.object_relation, 'url')
        self.assertEqual(url.value, self._get_pattern_value(x_misp_url))
        self.assertEqual(image_text.type, 'text')
        self.assertEqual(image_text.object_relation, 'image-text')
        self.assertEqual(image_text.value, self._get_pattern_value(x_misp_image_text))
        self.assertEqual(attachment.type, 'attachment')
        self.assertEqual(attachment.object_relation, 'attachment')
        self.assertEqual(attachment.value, self._get_pattern_value(x_misp_filename))
        self.assertEqual(
            self._get_data_value(attachment.data),
            self._get_pattern_value(payload_bin)
        )

    def _check_image_observable_object(self, attributes, observables):
        self.assertEqual(len(attributes), 4)
        file_object, artifact = observables.values()
        filename, image_text, attachment, url = attributes
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, file_object.name)
        self.assertEqual(image_text.type, 'text')
        self.assertEqual(image_text.object_relation, 'image-text')
        self.assertEqual(image_text.value, file_object.x_misp_image_text)
        self.assertEqual(attachment.type, 'attachment')
        self.assertEqual(attachment.object_relation, 'attachment')
        self.assertEqual(attachment.value, artifact.x_misp_filename)
        self.assertEqual(self._get_data_value(attachment.data), artifact.payload_bin)
        self.assertEqual(url.type, 'url')
        self.assertEqual(url.object_relation, 'url')
        self.assertEqual(url.value, artifact.x_misp_url)

    def _check_ip_port_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        _, ip_ref, _, domain_ref, dst_port, start = pattern[1:-1].split(' AND ')
        ip_dst, domain, port, first_seen = attributes
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'ip-dst')
        self.assertEqual(ip_dst.value, self._get_pattern_value(ip_ref[:-1]))
        self.assertEqual(domain.type, 'domain')
        self.assertEqual(domain.object_relation, 'domain')
        self.assertEqual(domain.value, self._get_pattern_value(domain_ref[:-1]))
        self.assertEqual(port.type, 'port')
        self.assertEqual(port.object_relation, 'dst-port')
        self.assertEqual(port.value, self._get_pattern_value(dst_port))
        self.assertEqual(first_seen.type, 'datetime')
        self.assertEqual(first_seen.object_relation, 'first-seen')
        self.assertEqual(
            self._datetime_to_str(first_seen.value),
            self._get_pattern_value(start)[:-1]
        )

    def _check_ip_port_observable_object(self, attributes, observables):
        self.assertEqual(len(attributes), 4)
        ip_dst, port, first_seen, domain = attributes
        network_traffic, address = observables.values()
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'ip-dst')
        self.assertEqual(ip_dst.value, address.value)
        self.assertEqual(port.type, 'port')
        self.assertEqual(port.object_relation, 'dst-port')
        self.assertEqual(port.value, network_traffic.dst_port)
        self.assertEqual(first_seen.type, 'datetime')
        self.assertEqual(first_seen.object_relation, 'first-seen')
        self.assertEqual(first_seen.value, network_traffic.start)
        self.assertEqual(domain.type, 'domain')
        self.assertEqual(domain.object_relation, 'domain')
        self.assertEqual(domain.value, network_traffic.x_misp_domain)

    def _check_legal_entity_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'legal-entity')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, business, registration_number, phone, website, logo = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual([business.value], identity.sectors)
        phone_info, website_info = identity.contact_information.split(' / ')
        self.assertEqual(phone_info, f"{phone.object_relation}: {phone.value}")
        self.assertEqual(website_info, f"{website.object_relation}: {website.value}")
        self.assertEqual(registration_number.value, identity.x_misp_registration_number)
        self.assertEqual(logo.value, identity.x_misp_logo['value'])
        self.assertEqual(self._get_data_value(logo.data), identity.x_misp_logo['data'])

    def _check_lnk_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 10)
        atime, ctime,  mtime, name, dir_ref, MD5, SHA1, SHA256, payload_bin, x_misp_filename, content_md5, size = pattern
        filename, path, md5, sha1, sha256, size_in_bytes, creation_time, modification_time, access_time, malware_sample = attributes
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, self._get_pattern_value(name))
        self.assertEqual(path.type, 'text')
        self.assertEqual(path.object_relation, 'path')
        self.assertEqual(path.value, self._get_pattern_value(dir_ref))
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, self._get_pattern_value(MD5))
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, self._get_pattern_value(SHA1))
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, self._get_pattern_value(SHA256))
        self.assertEqual(size_in_bytes.type, 'size-in-bytes')
        self.assertEqual(size_in_bytes.object_relation, 'size-in-bytes')
        self.assertEqual(size_in_bytes.value, self._get_pattern_value(size))
        self.assertEqual(creation_time.type, 'datetime')
        self.assertEqual(creation_time.object_relation, 'lnk-creation-time')
        self.assertEqual(
            self._datetime_to_str(creation_time.value),
            self._get_pattern_value(ctime)
        )
        self.assertEqual(modification_time.type, 'datetime')
        self.assertEqual(modification_time.object_relation, 'lnk-modification-time')
        self.assertEqual(
            self._datetime_to_str(modification_time.value),
            self._get_pattern_value(mtime)
        )
        self.assertEqual(access_time.type, 'datetime')
        self.assertEqual(access_time.object_relation, 'lnk-access-time')
        self.assertEqual(
            self._datetime_to_str(access_time.value),
            self._get_pattern_value(atime)
        )
        self.assertEqual(malware_sample.type, 'malware-sample')
        self.assertEqual(malware_sample.object_relation, 'malware-sample')
        self.assertEqual(
            malware_sample.value,
            f'{self._get_pattern_value(x_misp_filename)}|{self._get_pattern_value(content_md5)}'
        )
        self.assertEqual(
            self._get_data_value(malware_sample.data),
            self._get_pattern_value(payload_bin)
        )

    def _check_lnk_observable_object(self, attributes, observables):
        self.assertEqual(len(attributes), 10)
        md5, sha1, sha256, filename, atime, ctime, mtime, size, path, malware_sample = attributes
        file_object, directory, artifact = observables.values()
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, file_object.hashes['MD5'])
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, file_object.hashes['SHA-1'])
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, file_object.hashes['SHA-256'])
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, file_object.name)
        self.assertEqual(size.type, 'size-in-bytes')
        self.assertEqual(size.object_relation, 'size-in-bytes')
        self.assertEqual(size.value, file_object.size)
        self.assertEqual(path.type, 'text')
        self.assertEqual(path.object_relation, 'path')
        self.assertEqual(path.value, directory.path)
        self.assertEqual(malware_sample.type, 'malware-sample')
        self.assertEqual(malware_sample.object_relation, 'malware-sample')
        self.assertEqual(
            malware_sample.value,
            f"{artifact.x_misp_filename}|{artifact.hashes['MD5']}"
        )
        self.assertEqual(
            self._get_data_value(malware_sample.data),
            artifact.payload_bin
        )
        return atime, ctime, mtime

    def _check_mutex_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 3)
        name, description, operating_system = attributes
        name_pattern, x_misp_description, x_misp_operating_system = pattern[1:-1].split(' AND ')
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, self._get_pattern_value(name_pattern))
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, self._get_pattern_value(x_misp_description))
        self.assertEqual(operating_system.type, 'text')
        self.assertEqual(operating_system.object_relation, 'operating-system')
        self.assertEqual(operating_system.value, self._get_pattern_value(x_misp_operating_system))

    def _check_mutex_observable_object(self, attributes, mutex):
        self.assertEqual(len(attributes), 3)
        name, description, operating_system = attributes
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, mutex.name)
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'description')
        self.assertEqual(description.value, mutex.x_misp_description)
        self.assertEqual(operating_system.type, 'text')
        self.assertEqual(operating_system.object_relation, 'operating-system')
        self.assertEqual(operating_system.value, mutex.x_misp_operating_system)

    def _check_news_agency_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'news-agency')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, address, email, phone, attachment = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        address_info, email_info, phone_info = identity.contact_information.split(' / ')
        self.assertEqual(address_info, f'{address.object_relation}: {address.value}')
        self.assertEqual(email_info, f'{email.object_relation}: {email.value}')
        self.assertEqual(phone_info, f'{phone.object_relation}: {phone.value}')
        self.assertEqual(attachment.value, identity.x_misp_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            identity.x_misp_attachment['data']
        )

    def _check_organization_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'organization')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, role, alias, address, email, phone = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual(alias.value, identity.x_misp_alias)
        address_info, email_info, phone_info = identity.contact_information.split(' / ')
        self.assertEqual(address_info, f'{address.object_relation}: {address.value}')
        self.assertEqual(email_info, f'{email.object_relation}: {email.value}')
        self.assertEqual(phone_info, f'{phone.object_relation}: {phone.value}')
        return role

    def _check_parler_account_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        user_id, account_login, human, photo_data, photo_value = pattern[1:-1].split(' AND ')[1:]
        account_id, account_name, human_attribute, profile_photo = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, self._get_pattern_value(user_id))
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, self._get_pattern_value(account_login))
        self.assertEqual(human_attribute.type, 'boolean')
        self.assertEqual(human_attribute.object_relation, 'human')
        self.assertEqual(human_attribute.value, self._get_pattern_value(human))
        self.assertEqual(profile_photo.type, 'attachment')
        self.assertEqual(profile_photo.object_relation, 'profile-photo')
        self.assertEqual(profile_photo.value, self._get_pattern_value(photo_value))
        self.assertEqual(
            self._get_data_value(profile_photo.data),
            self._get_pattern_value(photo_data)
        )

    def _check_parler_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 4)
        account_id, account_name, human_attribute, profile_photo = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, observable.user_id)
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, observable.account_login)
        self.assertEqual(human_attribute.type, 'boolean')
        self.assertEqual(human_attribute.object_relation, 'human')
        self.assertEqual(human_attribute.value, observable.x_misp_human)
        self.assertEqual(profile_photo.type, 'attachment')
        self.assertEqual(profile_photo.object_relation, 'profile-photo')
        self.assertEqual(profile_photo.value, observable.x_misp_profile_photo['value'])
        self.assertEqual(
            self._get_data_value(profile_photo.data),
            observable.x_misp_profile_photo['data']
        )

    def _check_pe_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 15)
        entrypoint, imphash, number, pe_type, compilation, original, internal, description, file_version, lang_id, name, product_version, company, legal, impfuzzy = attributes
        IMPHASH, _number, _pe_type, address, _compilation, _original, _internal, _description, _file_version, _lang_id, _name, _product_version, _company, _legal, _impfuzzy = pattern
        self.assertEqual(entrypoint.type, 'text')
        self.assertEqual(entrypoint.object_relation, 'entrypoint-address')
        self.assertEqual(entrypoint.value, self._get_pattern_value(address))
        self.assertEqual(imphash.type, 'imphash')
        self.assertEqual(imphash.object_relation, 'imphash')
        self.assertEqual(imphash.value, self._get_pattern_value(IMPHASH))
        self.assertEqual(number.type, 'counter')
        self.assertEqual(number.object_relation, 'number-sections')
        self.assertEqual(number.value, self._get_pattern_value(_number))
        self.assertEqual(pe_type.type, 'text')
        self.assertEqual(pe_type.object_relation, 'type')
        self.assertEqual(pe_type.value, self._get_pattern_value(_pe_type))
        self.assertEqual(compilation.type, 'datetime')
        self.assertEqual(compilation.object_relation, 'compilation-timestamp')
        self.assertEqual(
            self._datetime_to_str(compilation.value),
            self._get_pattern_value(_compilation)
        )
        self.assertEqual(original.type, 'filename')
        self.assertEqual(original.object_relation, 'original-filename')
        self.assertEqual(original.value, self._get_pattern_value(_original))
        self.assertEqual(internal.type, 'filename')
        self.assertEqual(internal.object_relation, 'internal-filename')
        self.assertEqual(internal.value, self._get_pattern_value(_internal))
        self.assertEqual(description.type, 'text')
        self.assertEqual(description.object_relation, 'file-description')
        self.assertEqual(description.value, self._get_pattern_value(_description))
        self.assertEqual(file_version.type, 'text')
        self.assertEqual(file_version.object_relation, 'file-version')
        self.assertEqual(file_version.value, self._get_pattern_value(_file_version))
        self.assertEqual(lang_id.type, 'text')
        self.assertEqual(lang_id.object_relation, 'lang-id')
        self.assertEqual(lang_id.value, self._get_pattern_value(_lang_id))
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'product-name')
        self.assertEqual(name.value, self._get_pattern_value(_name))
        self.assertEqual(product_version.type, 'text')
        self.assertEqual(product_version.object_relation, 'product-version')
        self.assertEqual(product_version.value, self._get_pattern_value(_product_version))
        self.assertEqual(company.type, 'text')
        self.assertEqual(company.object_relation, 'company-name')
        self.assertEqual(company.value, self._get_pattern_value(_company))
        self.assertEqual(legal.type, 'text')
        self.assertEqual(legal.object_relation, 'legal-copyright')
        self.assertEqual(legal.value, self._get_pattern_value(_legal))
        self.assertEqual(impfuzzy.type, 'impfuzzy')
        self.assertEqual(impfuzzy.object_relation, 'impfuzzy')
        self.assertEqual(impfuzzy.value, self._get_pattern_value(_impfuzzy))

    def _check_pe_section_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 8)
        entropy, name, size_in_bytes, md5, sha1, sha256, sha512, ssdeep = attributes
        _entropy, _name, size, MD5, SHA1, SHA256, SHA512, SSDEEP = pattern
        self.assertEqual(entropy.type, 'float')
        self.assertEqual(entropy.object_relation, 'entropy')
        self.assertEqual(entropy.value, self._get_pattern_value(_entropy))
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, self._get_pattern_value(_name))
        self.assertEqual(size_in_bytes.type, 'size-in-bytes')
        self.assertEqual(size_in_bytes.object_relation, 'size-in-bytes')
        self.assertEqual(size_in_bytes.value, self._get_pattern_value(size))
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, self._get_pattern_value(MD5))
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, self._get_pattern_value(SHA1))
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, self._get_pattern_value(SHA256))
        self.assertEqual(sha512.type, 'sha512')
        self.assertEqual(sha512.object_relation, 'sha512')
        self.assertEqual(sha512.value, self._get_pattern_value(SHA512))
        self.assertEqual(ssdeep.type, 'ssdeep')
        self.assertEqual(ssdeep.object_relation, 'ssdeep')
        self.assertEqual(ssdeep.value, self._get_pattern_value(SSDEEP))

    def _check_reddit_account_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        user_id, account_login, description, avatar_data, avatar_value = pattern[1:-1].split(' AND ')[1:]
        account_id, account_name, description_attribute, account_avatar = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, self._get_pattern_value(user_id))
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, self._get_pattern_value(account_login))
        self.assertEqual(description_attribute.type, 'text')
        self.assertEqual(description_attribute.object_relation, 'description')
        self.assertEqual(description_attribute.value, self._get_pattern_value(description))
        self.assertEqual(account_avatar.type, 'attachment')
        self.assertEqual(account_avatar.object_relation, 'account-avatar')
        self.assertEqual(account_avatar.value, self._get_pattern_value(avatar_value))
        self.assertEqual(
            self._get_data_value(account_avatar.data),
            self._get_pattern_value(avatar_data)
        )

    def _check_reddit_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 4)
        account_id, account_name, account_avatar, description_attribute = attributes
        self.assertEqual(account_id.type, 'text')
        self.assertEqual(account_id.object_relation, 'account-id')
        self.assertEqual(account_id.value, observable.user_id)
        self.assertEqual(account_name.type, 'text')
        self.assertEqual(account_name.object_relation, 'account-name')
        self.assertEqual(account_name.value, observable.account_login)
        self.assertEqual(account_avatar.type, 'attachment')
        self.assertEqual(account_avatar.object_relation, 'account-avatar')
        self.assertEqual(account_avatar.value, observable.x_misp_account_avatar['value'])
        self.assertEqual(
            self._get_data_value(account_avatar.data),
            observable.x_misp_account_avatar['data']
        )
        self.assertEqual(description_attribute.type, 'text')
        self.assertEqual(description_attribute.object_relation, 'description')
        self.assertEqual(description_attribute.value, observable.x_misp_description)

    def _check_script_object(self, misp_object, stix_object):
        self.assertEqual(misp_object.uuid, stix_object.id.split('--')[1])
        self.assertEqual(misp_object.name, 'script')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(stix_object.created),
            self._timestamp_from_datetime(stix_object.modified)
        )
        self._check_object_labels(misp_object, stix_object.labels, False)
        filename, comment, language, script, state, attachment = misp_object.attributes
        self.assertEqual(filename.value, stix_object.name)
        self.assertEqual(comment.value, stix_object.description)
        self.assertEqual(script.value, stix_object.x_misp_script)
        self.assertEqual(attachment.value, stix_object.x_misp_script_as_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            stix_object.x_misp_script_as_attachment['data']
        )
        return language, state

    def _check_single_file_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 6)
        md5, sha1, sha256, filename, size_in_bytes, entropy = attributes
        MD5, SHA1, SHA256, name, size, x_misp_entropy = pattern
        self.assertEqual(md5.type, 'md5')
        self.assertEqual(md5.object_relation, 'md5')
        self.assertEqual(md5.value, self._get_pattern_value(MD5))
        self.assertEqual(sha1.type, 'sha1')
        self.assertEqual(sha1.object_relation, 'sha1')
        self.assertEqual(sha1.value, self._get_pattern_value(SHA1))
        self.assertEqual(sha256.type, 'sha256')
        self.assertEqual(sha256.object_relation, 'sha256')
        self.assertEqual(sha256.value, self._get_pattern_value(SHA256))
        self.assertEqual(filename.type, 'filename')
        self.assertEqual(filename.object_relation, 'filename')
        self.assertEqual(filename.value, self._get_pattern_value(name))
        self.assertEqual(size_in_bytes.type, 'size-in-bytes')
        self.assertEqual(size_in_bytes.object_relation, 'size-in-bytes')
        self.assertEqual(size_in_bytes.value, self._get_pattern_value(size))
        self.assertEqual(entropy.type, 'float')
        self.assertEqual(entropy.object_relation, 'entropy')
        self.assertEqual(entropy.value, self._get_pattern_value(x_misp_entropy))

    def _check_telegram_account_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 4)
        user_id, account_login, *phone_patterns = pattern[1:-1].split(' AND ')[1:]
        id_attribute, username, *phone_attributes = attributes
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, self._get_pattern_value(user_id))
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, self._get_pattern_value(account_login))
        for attribute, phone_pattern in zip(phone_attributes, phone_patterns):
            self.assertEqual(attribute.type, 'text')
            self.assertEqual(attribute.object_relation, 'phone')
            self.assertEqual(attribute.value, self._get_pattern_value(phone_pattern))

    def _check_telegram_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 4)
        user_id, username, *phone_attributes = attributes
        self.assertEqual(user_id.type, 'text')
        self.assertEqual(user_id.object_relation, 'id')
        self.assertEqual(user_id.value, observable.user_id)
        self.assertEqual(username.type, 'text')
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, observable.account_login)
        for attribute, phone_value in zip(phone_attributes, observable.x_misp_phone):
            self.assertEqual(attribute.type, 'text')
            self.assertEqual(attribute.object_relation, 'phone')
            self.assertEqual(attribute.value, phone_value)

    def _check_twitter_account_indicator_object(self, attributes, pattern):
        self.assertEqual(len(attributes), 5)
        display_name, user_id, account_login, followers, *image_pattern = pattern[1:-1].split(' AND ')[1:]
        displayed_name, id_attribute, name, followers_attribute, profile_image = attributes
        self.assertEqual(displayed_name.type, 'text')
        self.assertEqual(displayed_name.object_relation, 'displayed-name')
        self.assertEqual(displayed_name.value, self._get_pattern_value(display_name))
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, self._get_pattern_value(user_id))
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, self._get_pattern_value(account_login))
        self.assertEqual(followers_attribute.type, 'text')
        self.assertEqual(followers_attribute.object_relation, 'followers')
        self.assertEqual(followers_attribute.value, self._get_pattern_value(followers))
        self.assertEqual(profile_image.type, 'attachment')
        self.assertEqual(profile_image.object_relation, 'profile-image')
        image_data, image_value = image_pattern
        self.assertEqual(profile_image.value, self._get_pattern_value(image_value))
        self.assertEqual(
            self._get_data_value(profile_image.data),
            self._get_pattern_value(image_data)
        )

    def _check_twitter_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 5)
        id_attribute, name, displayed_name, followers_attribute, profile_image = attributes
        self.assertEqual(id_attribute.type, 'text')
        self.assertEqual(id_attribute.object_relation, 'id')
        self.assertEqual(id_attribute.value, observable.user_id)
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, observable.account_login)
        self.assertEqual(displayed_name.type, 'text')
        self.assertEqual(displayed_name.object_relation, 'displayed-name')
        self.assertEqual(displayed_name.value, observable.display_name)
        self.assertEqual(followers_attribute.type, 'text')
        self.assertEqual(followers_attribute.object_relation, 'followers')
        self.assertEqual(followers_attribute.value, observable.x_misp_followers)
        self.assertEqual(profile_image.type, 'attachment')
        self.assertEqual(profile_image.object_relation, 'profile-image')
        self.assertEqual(profile_image.value, observable.x_misp_profile_image['value'])
        self.assertEqual(
            self._get_data_value(profile_image.data),
            observable.x_misp_profile_image['data']
        )

    def _check_user_account_indicator_object(self, attributes, pattern_list):
        self.assertEqual(len(attributes), 11)
        account_p, display_p, credential, user_id_p, account_login, last_changed_p, groups1, groups2, gid, home_dir_p, user_avatar_data, user_avatar_value = pattern_list
        account_a, display_a, password, user_id_a, username, last_changed_a, group1, group2, group_id, home_dir_a, user_avatar = attributes
        self.assertEqual(account_a.type, 'text'),
        self.assertEqual(account_a.object_relation, 'account-type')
        self.assertEqual(account_a.value, self._get_pattern_value(account_p))
        self.assertEqual(display_a.type, 'text'),
        self.assertEqual(display_a.object_relation, 'display-name')
        self.assertEqual(display_a.value, self._get_pattern_value(display_p))
        self.assertEqual(password.type, 'text'),
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, self._get_pattern_value(credential))
        self.assertEqual(user_id_a.type, 'text'),
        self.assertEqual(user_id_a.object_relation, 'user-id')
        self.assertEqual(user_id_a.value, self._get_pattern_value(user_id_p))
        self.assertEqual(username.type, 'text'),
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, self._get_pattern_value(account_login))
        self.assertEqual(last_changed_a.type, 'datetime'),
        self.assertEqual(last_changed_a.object_relation, 'password_last_changed')
        self.assertEqual(
            self._datetime_to_str(last_changed_a.value),
            self._get_pattern_value(last_changed_p)
        )
        self.assertEqual(group1.type, 'text'),
        self.assertEqual(group1.object_relation, 'group')
        self.assertEqual(group1.value, self._get_pattern_value(groups1))
        self.assertEqual(group2.type, 'text'),
        self.assertEqual(group2.object_relation, 'group')
        self.assertEqual(group2.value, self._get_pattern_value(groups2))
        self.assertEqual(group_id.type, 'text'),
        self.assertEqual(group_id.object_relation, 'group-id')
        self.assertEqual(group_id.value, self._get_pattern_value(gid))
        self.assertEqual(home_dir_a.type, 'text'),
        self.assertEqual(home_dir_a.object_relation, 'home_dir')
        self.assertEqual(home_dir_a.value, self._get_pattern_value(home_dir_p))
        self.assertEqual(user_avatar.type, 'attachment'),
        self.assertEqual(user_avatar.object_relation, 'user-avatar')
        self.assertEqual(user_avatar.value, self._get_pattern_value(user_avatar_value))
        self.assertEqual(
            self._get_data_value(user_avatar.data),
            self._get_pattern_value(user_avatar_data)
        )

    def _check_user_account_observable_object(self, attributes, observable):
        self.assertEqual(len(attributes), 11)
        username, account_type, password, display_name, user_id, user_avatar, last_changed, group_id, group1, group2, home_dir = attributes
        self.assertEqual(username.type, 'text'),
        self.assertEqual(username.object_relation, 'username')
        self.assertEqual(username.value, observable.account_login)
        self.assertEqual(account_type.type, 'text'),
        self.assertEqual(account_type.object_relation, 'account-type')
        self.assertEqual(account_type.value, observable.account_type)
        self.assertEqual(display_name.type, 'text'),
        self.assertEqual(display_name.object_relation, 'display-name')
        self.assertEqual(display_name.value, observable.display_name)
        self.assertEqual(user_id.type, 'text'),
        self.assertEqual(user_id.object_relation, 'user-id')
        self.assertEqual(user_id.value, observable.user_id)
        self.assertEqual(user_avatar.type, 'attachment'),
        self.assertEqual(user_avatar.object_relation, 'user-avatar')
        self.assertEqual(user_avatar.value, observable.x_misp_user_avatar['value'])
        self.assertEqual(
            self._get_data_value(user_avatar.data),
            observable.x_misp_user_avatar['data']
        )
        extension = observable.extensions['unix-account-ext']
        self.assertEqual(group_id.type, 'text'),
        self.assertEqual(group_id.object_relation, 'group-id')
        self.assertEqual(group_id.value, extension.gid)
        for attribute, value in zip((group1, group2), extension.groups):
            self.assertEqual(attribute.type, 'text')
            self.assertEqual(attribute.object_relation, 'group')
            self.assertEqual(attribute.value, value)
        self.assertEqual(home_dir.type, 'text')
        self.assertEqual(home_dir.object_relation, 'home_dir')
        self.assertEqual(home_dir.value, extension.home_dir)
        return password, last_changed

    def _check_vulnerability_object(self, misp_object, vulnerability):
        self.assertEqual(misp_object.uuid, vulnerability.id.split('--')[1])
        self.assertEqual(misp_object.name, vulnerability.type)
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(vulnerability.created),
            self._timestamp_from_datetime(vulnerability.modified)
        )
        self._check_object_labels(misp_object, vulnerability.labels, False)
        external_id, external_ref1, external_ref2 = vulnerability.external_references
        cve_id, reference1, reference2, description, created, cvss_score, published = misp_object.attributes
        self._assert_multiple_equal(
            cve_id.value,
            vulnerability.name,
            external_id.external_id
        )
        self.assertEqual(reference1.value, external_ref1.url)
        self.assertEqual(reference2.value, external_ref2.url)
        self.assertEqual(description.value, vulnerability.description)
        self.assertEqual(self._datetime_to_str(created.value), vulnerability.x_misp_created)
        self.assertEqual(cvss_score.value, vulnerability.x_misp_cvss_score)
        self.assertEqual(self._datetime_to_str(published.value), vulnerability.x_misp_published)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _get_parsed_email_pattern(full_pattern):
        email_pattern = defaultdict(list)
        for pattern in full_pattern[1:-1].split(' AND '):
            identifier, value = pattern.split(' = ')
            email_pattern[identifier.split(':')[1]].append(value.strip("'"))
        return {key: value[0] if len(value) == 1 else value for key, value in email_pattern.items()}

    @staticmethod
    def _get_parsed_file_and_pe_pattern(full_pattern):
        file_pattern = []
        pe_pattern = []
        section_pattern = []
        for pattern in full_pattern[1:-1].split(' AND '):
            if ":extensions.'windows-pebinary-ext'." in pattern:
                if '.sections[' in pattern:
                    section_pattern.append(pattern)
                else:
                    pe_pattern.append(pattern)
            else:
                file_pattern.append(pattern)
        return file_pattern, pe_pattern, section_pattern

    @staticmethod
    def _get_parsed_file_pattern(full_pattern):
        file_pattern = []
        for pattern in full_pattern[1:-1].split(' AND '):
            if 'content_ref' not in pattern:
                file_pattern.append(pattern)
                continue
            if any(feature in pattern for feature in ('payload_bin', 'filename', 'hashes')):
                file_pattern.append(pattern)
        return file_pattern