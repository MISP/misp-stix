#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
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
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(indicator.created),
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
