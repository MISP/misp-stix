#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import unittest
from base64 import b64encode
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from stix.core import STIXPackage
from uuid import uuid5, UUID
from ._test_stix import TestSTIX

_DEFAULT_ORGNAME = 'MISP'


class TestCollectionSTIXExport(unittest.TestCase):
    def setUp(self):
        self._current_path = Path(__file__).parent

    def tearDown(self):
        for filename in self._current_path.glob('test_*_collection*.json.out'):
            os.remove(filename)


class TestCollectionSTIX1Export(TestCollectionSTIXExport):
    def _check_stix1_collection_export_results(self, to_test_file, reference_file):
        to_test = STIXPackage.from_xml(to_test_file).to_dict()
        reference = STIXPackage.from_xml(reference_file).to_dict()
        self.__recursive_feature_tests(reference, to_test, exclude=('id', 'timestamp'))

    def _check_stix1_export_results(self, to_test_file, reference_file):
        to_test = STIXPackage.from_xml(to_test_file).to_dict()
        reference = STIXPackage.from_xml(reference_file).to_dict()
        self.__recursive_feature_tests(reference, to_test, exclude=('id', 'timestamp'))

    def __check_observables(self, reference_observables, observables_to_test):
        for reference_observable, observable_to_test in zip(reference_observables, observables_to_test):
            uuid = '-'.join(part for part in reference_observable['object']['id'].split('-')[1:])
            for key, value in reference_observable['object']['properties'].items():
                if 'value' in key:
                    uuid = uuid5(UUID(uuid), value['value'])
                    break
            self.assertEqual(
                reference_observable['id'],
                f'{_DEFAULT_ORGNAME}:Observable-{uuid}'
            )
            self.assertEqual(reference_observable['id'], observable_to_test['id'])
            self.__recursive_feature_tests(
                reference_observable['object'],
                observable_to_test['object']
            )

    def __recursive_feature_tests(self, reference, to_test, exclude=tuple()):
        for key in (reference.keys() - exclude):
            try:
                self.assertEqual(reference[key], to_test[key])
            except AssertionError:
                if isinstance(reference[key], list):
                    if key == 'observables':
                        self.__check_observables(reference[key], to_test[key])
                        continue
                    for reference_value, value_to_test in zip(reference[key], to_test[key]):
                        self.__recursive_feature_tests(reference_value, value_to_test, exclude=exclude)
                else:
                    self.__recursive_feature_tests(reference[key], to_test[key])


class TestCollectionSTIX2Export(TestCollectionSTIXExport):
    def _check_stix2_results_export(self, to_test_file, reference_file):
        with open(to_test_file, 'rt', encoding='utf-8') as f:
            to_test = json.loads(f.read())
        with open(reference_file, 'rt', encoding='utf-8') as f:
            reference = json.loads(f.read())
        self.assertEqual(reference['objects'], to_test['objects'])


class TestSTIX2Export(TestSTIX):
    _labels = [
        'Threat-Report',
        'misp:tool="MISP-STIX-Converter"'
    ]

    @staticmethod
    def _add_attribute_ids_flag(event):
        for attribute in event['Attribute']:
            attribute['to_ids'] = True

    @staticmethod
    def _add_object_ids_flag(event):
        for misp_object in event['Object']:
            misp_object['Attribute'][0]['to_ids'] = True

    def _check_attack_pattern_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.external_references[0].external_id, meta['external_id'])
        for external_ref, ref in zip(stix_object.external_references[1:], meta['refs']):
            self.assertEqual(external_ref.url, ref)
        for killchain_phase, killchain in zip(stix_object.kill_chain_phases, meta['kill_chain']):
            killchain_name, *_, phase_name = killchain.split(':')
            self.assertEqual(killchain_phase.kill_chain_name, killchain_name)
            self.assertEqual(killchain_phase.phase_name, phase_name)

    def _check_attack_pattern_object(self, attack_pattern, misp_object, identity_id):
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self.assertEqual(attack_pattern.created_by_ref, identity_id)
        self._check_killchain(attack_pattern.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, attack_pattern.labels, to_ids=False)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(attack_pattern.created, timestamp)
        self.assertEqual(attack_pattern.modified, timestamp)
        id_, name, summary, weakness1, weakness2, prerequisite, solution = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(attack_pattern.name, name)
        self.assertEqual(attack_pattern.description, summary)
        self._check_external_reference(
            attack_pattern.external_references[0],
            'capec',
            f'CAPEC-{id_}'
        )
        self.assertEqual(attack_pattern.x_misp_related_weakness, [weakness1, weakness2])
        self.assertEqual(attack_pattern.x_misp_prerequisites, prerequisite)
        self.assertEqual(attack_pattern.x_misp_solutions, solution.replace("'", "\\'"))

    def _check_attribute_campaign_features(self, campaign, attribute, identity_id, object_ref):
        self._assert_multiple_equal(
            campaign.id,
            f"campaign--{attribute['uuid']}",
            object_ref
        )
        self.assertEqual(campaign.type, 'campaign')
        self.assertEqual(campaign.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, campaign.labels)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(campaign.created, timestamp)
        self.assertEqual(campaign.modified, timestamp)

    def _check_attribute_indicator_features(self, indicator, attribute, identity_id, object_ref):
        self._check_indicator_features(indicator, identity_id, object_ref, attribute['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], attribute['category'])
        self._check_attribute_labels(attribute, indicator.labels)
        self._check_indicator_time_features(indicator, attribute['timestamp'])

    def _check_attribute_labels(self, attribute, labels):
        if attribute.get('to_ids'):
            type_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{attribute["to_ids"]}"')
        else:
            type_label, category_label = labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')

    def _check_attribute_observable_features(self, observed_data, attribute, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, attribute['uuid'])
        self._check_attribute_labels(attribute, observed_data.labels)
        self._check_observable_time_features(observed_data, attribute['timestamp'])

    def _check_attribute_vulnerability_features(self, vulnerability, attribute, identity_id, object_ref):
        self._assert_multiple_equal(
            vulnerability.id,
            f"vulnerability--{attribute['uuid']}",
            object_ref
        )
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, vulnerability.labels)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(vulnerability.created, timestamp)
        self.assertEqual(vulnerability.modified, timestamp)

    def _check_course_of_action_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.external_references[0].external_id, meta['external_id'])
        for external_ref, ref in zip(stix_object.external_references[1:], meta['refs']):
            self.assertEqual(external_ref.url, ref)

    def _check_course_of_action_object(self, course_of_action, misp_object, identity_id):
        self.assertEqual(course_of_action.type, 'course-of-action')
        self.assertEqual(course_of_action.created_by_ref, identity_id)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(course_of_action.created, timestamp)
        self.assertEqual(course_of_action.modified, timestamp)
        name, description, *attributes = misp_object['Attribute']
        self.assertEqual(course_of_action.name, name['value'])
        self.assertEqual(course_of_action.description, description['value'])
        for attribute in attributes:
            self.assertEqual(
                getattr(
                    course_of_action,
                    f"x_misp_{attribute['object_relation']}"
                ),
                attribute['value']
            )

    def _check_custom_galaxy_features(self, stix_object, galaxy, timestamp):
        cluster = galaxy['GalaxyCluster'][0]
        self.assertEqual(stix_object.type, 'x-misp-galaxy-cluster')
        self.assertEqual(stix_object.id, f"x-misp-galaxy-cluster--{cluster['uuid']}")
        self.assertEqual(stix_object.created, timestamp)
        self.assertEqual(stix_object.modified, timestamp)
        self.assertEqual(stix_object.x_misp_name, galaxy['name'])
        self.assertEqual(stix_object.x_misp_type, cluster['type'])
        self.assertEqual(stix_object.x_misp_value, cluster['value'])
        self.assertEqual(
            stix_object.x_misp_description,
            f"{galaxy['description']} | {cluster['description']}"
        )
        self.assertEqual(stix_object.labels[0], f'misp:galaxy-name="{galaxy["name"]}"')
        self.assertEqual(stix_object.labels[1], f'misp:galaxy-type="{galaxy["type"]}"')

    def _check_email_address(self, address_object, address, display_name=None):
        self.assertEqual(address_object.type, 'email-addr')
        self.assertEqual(address_object.value, address)
        if display_name is not None:
            self.assertEqual(address_object.display_name, display_name)

    def _check_employee_object(self, employee, misp_object, employee_ref, identity_id):
        self.assertEqual(employee.type, 'identity')
        self._assert_multiple_equal(
            employee.id,
            employee_ref,
            f"identity--{misp_object['uuid']}"
        )
        self.assertEqual(employee.identity_class, 'individual')
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(employee.created, timestamp)
        self.assertEqual(employee.modified, timestamp)
        self.assertEqual(employee.created_by_ref, identity_id)
        first_name, last_name, description, email, employee_type = misp_object['Attribute']
        self.assertEqual(employee.name, f"{first_name['value']} {last_name['value']}")
        self.assertEqual(employee.description, description['value'])
        self.assertEqual(
            employee.contact_information,
            f"{email['object_relation']}: {email['value']}"
        )
        return employee_type['value']

    def _check_external_reference(self, reference, source_name, value):
        self.assertEqual(reference.source_name, source_name)
        self.assertEqual(reference.external_id, value)

    def _check_galaxy_features(self, stix_object, galaxy, timestamp):
        cluster = galaxy['GalaxyCluster'][0]
        self.assertEqual(stix_object.id, f"{stix_object.type}--{cluster['uuid']}")
        self.assertEqual(stix_object.created, timestamp)
        self.assertEqual(stix_object.modified, timestamp)
        self.assertEqual(stix_object.name, cluster['value'])
        description = galaxy['description']
        if cluster.get('description'):
            description = f"{description} | {cluster['description']}"
        self.assertEqual(stix_object.description, description)
        self.assertEqual(stix_object.labels[0], f'misp:galaxy-name="{galaxy["name"]}"')
        self.assertEqual(stix_object.labels[1], f'misp:galaxy-type="{galaxy["type"]}"')
        if cluster.get('meta'):
            getattr(
                self, f"_check_{stix_object.type.replace('-', '_')}_meta_fields"
            )(
                stix_object, cluster['meta']
            )

    def _check_identity_features(self, identity, orgc, timestamp):
        identity_id = f"identity--{orgc['uuid']}"
        self.assertEqual(identity.type, 'identity')
        self.assertEqual(identity.id, identity_id)
        self.assertEqual(identity.name, orgc['name'])
        self.assertEqual(identity.identity_class, 'organization')
        self.assertEqual(identity.created.timestamp(), timestamp.timestamp())
        self.assertEqual(identity.modified.timestamp(), timestamp.timestamp())
        return identity_id

    def _check_identities_from_sighting(self, identities, uuids, names):
        for identity in identities:
            self.assertIn(identity.id, uuids)
            self.assertIn(identity.name, names)

    def _check_indicator_features(self, indicator, identity_id, object_ref, object_uuid):
        self._assert_multiple_equal(
            indicator.id,
            f"indicator--{object_uuid}",
            object_ref
        )
        self.assertEqual(indicator.type, 'indicator')
        self.assertEqual(indicator.created_by_ref, identity_id)

    def _check_indicator_time_features(self, indicator, timestamp):
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(indicator.created, timestamp)
        self.assertEqual(indicator.modified, timestamp)
        self.assertEqual(indicator.valid_from, timestamp)

    def _check_intrusion_set_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.aliases, meta['synonyms'])
        self.assertEqual(stix_object.external_references[0].external_id, meta['external_id'])
        for external_ref, ref in zip(stix_object.external_references[1:], meta['refs']):
            self.assertEqual(external_ref.url, ref)

    def _check_killchain(self, killchain, category):
        self.assertEqual(killchain['kill_chain_name'], 'misp-category')
        self.assertEqual(killchain['phase_name'], category)

    def _check_legal_entity_object_features(self, legal_entity, misp_object, legal_entity_ref, identity_id):
        self.assertEqual(legal_entity.type, 'identity')
        self._assert_multiple_equal(
            legal_entity.id,
            legal_entity_ref,
            f"identity--{misp_object['uuid']}"
        )
        self.assertEqual(legal_entity.identity_class, 'organization')
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(legal_entity.created, timestamp)
        self.assertEqual(legal_entity.modified, timestamp)
        self.assertEqual(legal_entity.created_by_ref, identity_id)
        name, description, business, phone, website, registration_number, logo = misp_object['Attribute']
        self.assertEqual(legal_entity.name, name['value'])
        self.assertEqual(legal_entity.description, description['value'])
        self.assertEqual(legal_entity.sectors, [business['value']])
        self.assertEqual(
            legal_entity.contact_information,
            f"{phone['object_relation']}: {phone['value']} / {website['object_relation']}: {website['value']}"
        )
        self.assertEqual(
            legal_entity.x_misp_registration_number,
            registration_number['value']
        )
        self.assertEqual(legal_entity.x_misp_logo['value'], logo['value'])
        data = logo['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(legal_entity.x_misp_logo['data'], data)

    def _check_malware_meta_fields(self, stix_object, meta):
        if hasattr(stix_object, 'aliases'):
            self.assertEqual(stix_object.aliases, meta['synonyms'])
        else:
            self.assertEqual(stix_object.x_misp_synonyms, meta['synonyms'])
        self.assertEqual(stix_object.external_references[0].external_id, meta['external_id'])
        for external_ref, ref in zip(stix_object.external_references[1:], meta['refs']):
            self.assertEqual(external_ref.url, ref)
        self.assertEqual(stix_object.x_misp_mitre_platforms, meta['mitre_platforms'])

    def _check_object_indicator_features(self, indicator, misp_object, identity_id, object_ref):
        self._check_indicator_features(indicator, identity_id, object_ref, misp_object['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, indicator.labels, to_ids=True)
        self._check_indicator_time_features(indicator, misp_object['timestamp'])

    def _check_object_labels(self, misp_object, labels, to_ids=None):
        if to_ids is not None:
            name_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{to_ids}"')
        else:
            name_label, category_label = labels
        self.assertEqual(name_label, f'misp:name="{misp_object["name"]}"')
        self.assertEqual(category_label, f'misp:meta-category="{misp_object["meta-category"]}"')

    def _check_object_observable_features(self, observed_data, misp_object, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, misp_object['uuid'])
        self._check_object_labels(misp_object, observed_data.labels, to_ids=False)
        self._check_observable_time_features(observed_data, misp_object['timestamp'])

    def _check_object_vulnerability_features(self, vulnerability, misp_object, identity_id, object_ref):
        self._assert_multiple_equal(
            vulnerability.id,
            f"vulnerability--{misp_object['uuid']}",
            object_ref
        )
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_object_labels(misp_object, vulnerability.labels, to_ids=False)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(vulnerability.modified, timestamp)
        cve, cvss, summary, created, published, references1, references2 = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(vulnerability.name, cve)
        self.assertEqual(vulnerability.description, summary)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(vulnerability.created, timestamp)
        self.assertEqual(vulnerability.modified, timestamp)
        cve_ref, url1, url2 = vulnerability.external_references
        self.assertEqual(cve_ref.source_name, 'cve')
        self.assertEqual(cve_ref.external_id, cve)
        self.assertEqual(url1.source_name, 'url')
        self.assertEqual(url1.url, references1)
        self.assertEqual(url2.source_name, 'url')
        self.assertEqual(url2.url, references2)
        self.assertEqual(vulnerability.x_misp_created, created)
        self.assertEqual(vulnerability.x_misp_cvss_score, cvss)
        self.assertEqual(vulnerability.x_misp_published, published)

    def _check_observable_features(self, observed_data, identity_id, object_ref, object_uuid):
        self._assert_multiple_equal(
            observed_data.id,
            f"observed-data--{object_uuid}",
            object_ref
        )
        self.assertEqual(observed_data.type, 'observed-data')
        self.assertEqual(observed_data.created_by_ref, identity_id)
        self.assertEqual(observed_data.number_observed, 1)

    def _check_observable_time_features(self, observed_data, timestamp):
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(observed_data.created, timestamp)
        self.assertEqual(observed_data.modified, timestamp)
        self.assertEqual(observed_data.first_observed, timestamp)
        self.assertEqual(observed_data.last_observed, timestamp)

    def _check_pe_and_section_observable(self, extension, pe, section):
        _type, compilation, entrypoint, original, internal, desc, version, lang, prod_name, prod_version, company, copyright, sections, imphash, impfuzzy = (attribute['value'] for attribute in pe['Attribute'])
        self.assertEqual(extension.pe_type, _type)
        self.assertEqual(extension.imphash, imphash)
        self.assertEqual(extension.number_of_sections, int(sections))
        self.assertEqual(extension.optional_header['address_of_entry_point'], int(entrypoint))
        self.assertEqual(extension.x_misp_company_name, company)
        self.assertEqual(extension.x_misp_compilation_timestamp, compilation)
        self.assertEqual(extension.x_misp_file_description, desc)
        self.assertEqual(extension.x_misp_file_version, version)
        self.assertEqual(extension.x_misp_impfuzzy, impfuzzy)
        self.assertEqual(extension.x_misp_internal_filename, internal)
        self.assertEqual(extension.x_misp_lang_id, lang)
        self.assertEqual(extension.x_misp_legal_copyright, copyright)
        self.assertEqual(extension.x_misp_original_filename, original)
        self.assertEqual(extension.x_misp_product_name, prod_name)
        self.assertEqual(extension.x_misp_product_version, prod_version)
        name, size, entropy, md5, sha1, sha256, sha512, ssdeep = (attribute['value'] for attribute in section['Attribute'])
        section = extension.sections[0]
        self.assertEqual(section.name, name)
        self.assertEqual(section.size, int(size))
        self.assertEqual(section.entropy, float(entropy))
        hashes = section.hashes
        self.assertEqual(hashes['MD5'], md5)
        self.assertEqual(hashes['SHA-1'], sha1)
        self.assertEqual(hashes['SHA-256'], sha256)
        self.assertEqual(hashes['SHA-512'], sha512)
        self.assertEqual(hashes['ssdeep' if 'ssdeep' in hashes else 'SSDEEP'], ssdeep)

    def _check_pe_and_section_pattern(self, pattern, pe, section):
        _type, _compilation, _entrypoint, _original, _internal, _desc, _version, _lang, _prod_name, _prod_version, _company, _copyright, _sections, _imphash, _impfuzzy = (attribute['value'] for attribute in pe['Attribute'])
        imphash_, sections_, type_, entrypoint_, compilation_, original_, internal_, desc_, version_, lang_, prod_name_, prod_version_, company_, copyright_, impfuzzy_ = pattern[:15]
        prefix = "file:extensions.'windows-pebinary-ext'"
        self.assertEqual(imphash_, f"{prefix}.imphash = '{_imphash}'")
        self.assertEqual(sections_, f"{prefix}.number_of_sections = '{_sections}'")
        self.assertEqual(type_, f"{prefix}.pe_type = '{_type}'")
        self.assertEqual(entrypoint_, f"{prefix}.optional_header.address_of_entry_point = '{_entrypoint}'")
        self.assertEqual(compilation_, f"{prefix}.x_misp_compilation_timestamp = '{_compilation}'")
        self.assertEqual(original_, f"{prefix}.x_misp_original_filename = '{_original}'")
        self.assertEqual(internal_, f"{prefix}.x_misp_internal_filename = '{_internal}'")
        self.assertEqual(desc_, f"{prefix}.x_misp_file_description = '{_desc}'")
        self.assertEqual(version_, f"{prefix}.x_misp_file_version = '{_version}'")
        self.assertEqual(lang_, f"{prefix}.x_misp_lang_id = '{_lang}'")
        self.assertEqual(prod_name_, f"{prefix}.x_misp_product_name = '{_prod_name}'")
        self.assertEqual(prod_version_, f"{prefix}.x_misp_product_version = '{_prod_version}'")
        self.assertEqual(company_, f"{prefix}.x_misp_company_name = '{_company}'")
        self.assertEqual(copyright_, f"{prefix}.x_misp_legal_copyright = '{_copyright}'")
        self.assertEqual(impfuzzy_, f"{prefix}.x_misp_impfuzzy = '{_impfuzzy}'")
        _name, _size, _entropy, _md5, _sha1, _sha256, _sha512, _ssdeep = (attribute['value'] for attribute in section['Attribute'])
        entropy_, name_, size_, md5_, sha1_, sha256_, sha512_, ssdeep_ = pattern[15:]
        prefix = f"{prefix}.sections[0]"
        self.assertEqual(entropy_, f"{prefix}.entropy = '{_entropy}'")
        self.assertEqual(name_, f"{prefix}.name = '{_name}'")
        self.assertEqual(size_, f"{prefix}.size = '{_size}'")
        self.assertEqual(md5_, f"{prefix}.hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"{prefix}.hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"{prefix}.hashes.SHA256 = '{_sha256}'")
        self.assertEqual(sha512_, f"{prefix}.hashes.SHA512 = '{_sha512}'")
        self.assertEqual(ssdeep_, f"{prefix}.hashes.SSDEEP = '{_ssdeep}'")

    def _check_person_object(self, identity, misp_object, person_ref, identity_id):
        self.assertEqual(identity.type, 'identity')
        self._assert_multiple_equal(
            identity.id,
            person_ref,
            f"identity--{misp_object['uuid']}"
        )
        self.assertEqual(identity.identity_class, 'individual')
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(identity.created, timestamp)
        self.assertEqual(identity.modified, timestamp)
        self.assertEqual(identity.created_by_ref, identity_id)
        first_name, last_name, nationality, passport, phone, role = misp_object['Attribute']
        self.assertEqual(identity.name, f"{first_name['value']} {last_name['value']}")
        self.assertEqual(
            identity.contact_information,
            f"{phone['object_relation']}: {phone['value']}"
        )
        self.assertEqual(identity.x_misp_nationality, nationality['value'])
        self.assertEqual(identity.x_misp_passport_number, passport['value'])
        return role['value']

    def _check_relationship_features(self, relationship, source_id, target_id, relationship_type, timestamp):
        self.assertEqual(relationship.type, 'relationship')
        self.assertEqual(relationship.source_ref, source_id)
        self.assertEqual(relationship.target_ref, target_id)
        self.assertEqual(relationship.relationship_type, relationship_type)
        self._assert_multiple_equal(
            timestamp,
            relationship.created,
            relationship.modified
        )

    def _check_report_features(self, report, event, identity_id, timestamp):
        self.assertEqual(report.type, 'report')
        self.assertEqual(report.id, f"report--{event['uuid']}")
        self.assertEqual(report.created_by_ref, identity_id)
        self.assertEqual(report.labels, self._labels)
        self.assertEqual(report.name, event['info'])
        self._assert_multiple_equal(
            timestamp,
            report.created,
            report.modified
        )
        return report.object_refs

    def _check_sighting_features(self, stix_sighting, misp_sighting, object_id, identity_id):
        self.assertEqual(stix_sighting.type, 'sighting')
        self.assertEqual(stix_sighting.id, f"sighting--{misp_sighting['uuid']}")
        self._assert_multiple_equal(
            stix_sighting.created,
            stix_sighting.modified,
            self._datetime_from_timestamp(misp_sighting['date_sighting'])
        )
        self.assertEqual(stix_sighting.sighting_of_ref, object_id)
        self.assertEqual(stix_sighting.where_sighted_refs, [identity_id])

    def _check_threat_actor_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.aliases, meta['synonyms'])

    def _check_tool_meta_fields(self, stix_object, meta):
        if hasattr(stix_object, 'aliases'):
            self.assertEqual(stix_object.aliases, meta['synonyms'])
        else:
            self.assertEqual(stix_object.x_misp_synonyms, meta['synonyms'])
        self.assertEqual(stix_object.external_references[0].external_id, meta['external_id'])
        for external_ref, ref in zip(stix_object.external_references[1:], meta['refs']):
            self.assertEqual(external_ref.url, ref)
        self.assertEqual(stix_object.x_misp_mitre_platforms, meta['mitre_platforms'])

    def _check_vulnerability_meta_fields(self, stix_object, meta):
        self.assertEqual(
            stix_object.external_references[0],
            {
                'source_name': 'cve',
                'external_id': meta['aliases'][0]
            }
        )

    @staticmethod
    def _datetime_from_timestamp(timestamp):
        return datetime.fromtimestamp(int(timestamp), timezone.utc)

    @staticmethod
    def _parse_AS_value(value):
        if value.startswith('AS'):
            return int(value[2:])
        return int(value)

    def _populate_documentation(self, attribute = None, misp_object = None, galaxy = None, **kwargs):
        if attribute is not None:
            self._populate_attributes_documentation(attribute, **kwargs)
        elif misp_object is not None:
            self._populate_objects_documentation(misp_object, **kwargs)
        elif galaxy is not None:
            self._populate_galaxies_documentation(galaxy, **kwargs)

    @staticmethod
    def _reassemble_pattern(pattern):
        reassembled = []
        middle = False
        for feature in pattern.split(' AND '):
            if feature.startswith('('):
                pattern_part = [feature]
                middle = True
                continue
            if feature.endswith(')'):
                pattern_part.append(feature)
                reassembled.append(' AND '.join(pattern_part))
                middle = False
                continue
            if middle:
                pattern_part.append(feature)
            else:
                reassembled.append(feature)
        return reassembled

    @staticmethod
    def _remove_attribute_ids_flag(event):
        for attribute in event['Attribute']:
            attribute['to_ids'] = False

    @staticmethod
    def _remove_object_ids_flags(event):
        for misp_object in event['Object']:
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = False

    def _run_custom_attribute_tests(self, attribute, custom_object, object_ref, identity_id):
        attribute_type = attribute['type']
        category = attribute['category']
        custom_type = f"x-misp-attribute"
        self.assertEqual(custom_object.type, custom_type)
        self._assert_multiple_equal(
            custom_object.id,
            f"{custom_type}--{attribute['uuid']}",
            object_ref
        )
        self.assertEqual(custom_object.created_by_ref, identity_id)
        self.assertEqual(custom_object.labels[0], f'misp:type="{attribute_type}"')
        self.assertEqual(custom_object.labels[1], f'misp:category="{category}"')
        if attribute.get('to_ids', False):
            self.assertEqual(custom_object.labels[2], 'misp:to_ids="True"')
        self.assertEqual(custom_object.x_misp_type, attribute_type)
        self.assertEqual(custom_object.x_misp_category, category)
        if attribute.get('comment'):
            self.assertEqual(custom_object.x_misp_comment, attribute['comment'])
        self.assertEqual(custom_object.x_misp_value, attribute['value'])

    def _run_custom_object_tests(self, misp_object, custom_object, object_ref, identity_id):
        name = misp_object['name']
        category = misp_object['meta-category']
        custom_type = 'x-misp-object'
        self.assertEqual(custom_object.type, custom_type)
        self._assert_multiple_equal(
            custom_object.id,
            f"{custom_type}--{misp_object['uuid']}",
            object_ref
        )
        self.assertEqual(custom_object.created_by_ref, identity_id)
        self.assertEqual(custom_object.labels[0], f'misp:name="{name}"')
        self.assertEqual(custom_object.labels[1], f'misp:meta-category="{category}"')
        self.assertEqual(custom_object.x_misp_name, name)
        self.assertEqual(custom_object.x_misp_meta_category, category)
        if misp_object.get('comment'):
            self.assertEqual(custom_object.x_misp_comment, misp_object['comment'])
        for custom_attribute, attribute in zip(custom_object.x_misp_attributes, misp_object['Attribute']):
            for feature in ('type', 'object_relation', 'value'):
                try:
                    self.assertEqual(custom_attribute[feature], attribute[feature])
                except AssertionError:
                    if '(s)' in attribute[feature]:
                        self.assertEqual(custom_attribute[feature], attribute[feature].replace('(s)', ''))
            for feature in ('category', 'comment', 'to_ids', 'uuid'):
                if attribute.get(feature):
                    self.assertEqual(custom_attribute[feature], attribute[feature])
            if attribute.get('data'):
                data = attribute['data']
                if not isinstance(data, str):
                    data = b64encode(data.getvalue()).decode()
                self.assertEqual(custom_attribute['data'], data)

    def _sanitize_documentation(self, documentation):
        if isinstance(documentation, list):
            return [self._sanitize_documentation(value) for value in documentation]
        sanitized = {}
        for key, value in documentation.items():
            if key == 'to_ids':
                continue
            sanitized[key] = self._sanitize_documentation(value) if isinstance(value, (dict, list)) else value
        return sanitized

    def _sanitize_pattern_value(self, value):
        sanitized = self._sanitize_registry_key_value(value)
        return sanitized.replace("'", "\\'").replace('"', '\\\\"')

    def _sanitize_registry_key_value(self, value: str) -> str:
        sanitized = self._sanitize_value(value.strip()).replace('\\', '\\\\')
        if '%' not in sanitized or '\\\\%' in sanitized:
            return sanitized
        if '\\%' in sanitized:
            return sanitized.replace('\\%', '\\\\%')
        return sanitized.replace('%', '\\\\%')

    def _sanitize_value(self, value):
        for character in ('"', "'"):
            if value.startswith(character):
                return self._sanitize_value(value[1:])
            if value.endswith(character):
                return self._sanitize_value(value[:-1])
        return value


class TestSTIX20Export(TestSTIX2Export):
    _attributes_v20 = defaultdict(lambda: defaultdict(dict))
    _objects_v20 = defaultdict(lambda: defaultdict(dict))
    _galaxies_v20 = defaultdict(lambda: defaultdict(dict))

    def _populate_attributes_documentation(self, attribute, **kwargs):
        attribute_type = attribute['type']
        if 'MISP' not in self._attributes_v20[attribute_type]:
            self._attributes_v20[attribute_type]['MISP'] = self._sanitize_documentation(attribute)
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = object_type.replace('_', ' ').title()
            self._attributes_v20[attribute_type]['STIX'][feature] = documented

    def _populate_galaxies_documentation(self, galaxy, name=None, summary=None, **kwargs):
        if name is None:
            name = galaxy['name']
        if 'MISP' not in self._galaxies_v20[name]:
            self._galaxies_v20[name]['MISP'] = galaxy
        if summary is not None:
            self._galaxies_v20['summary'][name] = summary
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
            self._galaxies_v20[name]['STIX'][feature] = documented

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        if 'MISP' not in self._objects_v20[name]:
            self._objects_v20[name]['MISP'] = self._sanitize_documentation(misp_object)
        if summary is not None:
            self._objects_v20['summary'][name] = summary
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
            self._objects_v20[name]['STIX'][feature] = documented


class TestSTIX21Export(TestSTIX2Export):
    _attributes_v21 = defaultdict(lambda: defaultdict(dict))
    _objects_v21 = defaultdict(lambda: defaultdict(dict))
    _galaxies_v21 = defaultdict(lambda: defaultdict(dict))

    def _populate_attributes_documentation(self, attribute, **kwargs):
        feature = attribute['type']
        if 'MISP' not in self._attributes_v21[feature]:
            self._attributes_v21[feature]['MISP'] = self._sanitize_documentation(attribute)
        if 'observed_data' in kwargs:
            documented = [json.loads(observable.serialize()) for observable in kwargs['observed_data']]
            self._attributes_v21[feature]['STIX']['Observed Data'] = documented
        else:
            for object_type, stix_object in kwargs.items():
                documented = json.loads(stix_object.serialize())
                self._attributes_v21[feature]['STIX'][object_type.capitalize()] = documented

    def _populate_galaxies_documentation(self, galaxy, name=None, summary=None, **kwargs):
        if name is None:
            name = galaxy['name']
        if 'MISP' not in self._galaxies_v21[name]:
            self._galaxies_v21[name]['MISP'] = galaxy
        if summary is not None:
            self._galaxies_v21['summary'][name] = summary
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
            self._galaxies_v21[name]['STIX'][feature] = documented

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        if 'MISP' not in self._objects_v21[name]:
            self._objects_v21[name]['MISP'] = self._sanitize_documentation(misp_object)
        if summary is not None:
            self._objects_v21['summary'][name] = summary
        if 'observed_data' in kwargs:
            documented = [json.loads(observable.serialize()) for observable in kwargs['observed_data']]
            self._objects_v21[name]['STIX']['Observed Data'] = documented
        else:
            for object_type, stix_object in kwargs.items():
                documented = json.loads(stix_object.serialize())
                feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
                self._objects_v21[name]['STIX'][feature] = documented
