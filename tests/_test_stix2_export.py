#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import unittest
from datetime import datetime
from misp_stix_converter import MISPtoSTIX20Parser, MISPtoSTIX21Parser
from pathlib import Path


class TestCollectionSTIX2Export(unittest.TestCase):
    def setUp(self):
        self._current_path = Path(__file__).parent

    def tearDown(self):
        for filename in self._current_path.glob('test_events_collection*.json.out'):
            os.remove(filename)

    def _check_results_export(self, to_test_name, reference_name):
        with open(self._current_path / to_test_name, 'rt', encoding='utf-8') as f:
            to_test = json.loads(f.read())
        print(json.dumps(to_test, indent=4))
        with open(self._current_path / reference_name, 'rt', encoding='utf-8') as f:
            reference = json.loads(f.read())
        self.assertEqual(reference['objects'], to_test['objects'])


class TestSTIX2Export(unittest.TestCase):
    _labels = [
        'Threat-Report',
        'misp:tool="MISP-STIX-Converter"'
    ]

    @staticmethod
    def _add_attribute_ids_flag(event):
        for attribute in event['Event']['Attribute']:
            attribute['to_ids'] = True

    @staticmethod
    def _add_object_ids_flag(event):
        for misp_object in event['Event']['Object']:
            misp_object['Attribute'][0]['to_ids'] = True

    def _check_attribute_campaign_features(self, campaign, attribute, identity_id, object_ref):
        uuid = f"campaign--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(campaign.id, uuid)
        self.assertEqual(campaign.type, 'campaign')
        self.assertEqual(campaign.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, campaign.labels)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
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
        uuid = f"vulnerability--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(vulnerability.id, uuid)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, vulnerability.labels)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(vulnerability.created, timestamp)
        self.assertEqual(vulnerability.modified, timestamp)

    def _check_external_reference(self, reference, source_name, value):
        self.assertEqual(reference.source_name, source_name)
        self.assertEqual(reference.external_id, value)

    def _check_galaxy_features(self, stix_object, galaxy, timestamp, killchain, synonyms):
        cluster = galaxy['GalaxyCluster'][0]
        self.assertEqual(stix_object.created, timestamp)
        self.assertEqual(stix_object.modified, timestamp)
        self.assertEqual(stix_object.name, cluster['value'])
        self.assertEqual(stix_object.description, f"{galaxy['description']} | {cluster['description']}")
        self.assertEqual(stix_object.labels[0], f'misp:name="{galaxy["name"]}"')
        if killchain:
            self.assertEqual(stix_object.kill_chain_phases[0]['phase_name'], cluster['type'])
        if synonyms:
            self.assertEqual(stix_object.aliases[0], cluster['meta']['synonyms'][0])

    def _check_identity_features(self, identity, orgc, timestamp):
        identity_id = f"identity--{orgc['uuid']}"
        self.assertEqual(identity.type, 'identity')
        self.assertEqual(identity.id, identity_id)
        self.assertEqual(identity.name, orgc['name'])
        self.assertEqual(identity.identity_class, 'organization')
        self.assertEqual(identity.created, timestamp)
        self.assertEqual(identity.modified, timestamp)
        return identity_id

    def _check_indicator_features(self, indicator, identity_id, object_ref, object_uuid):
        uuid = f"indicator--{object_uuid}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(indicator.id, uuid)
        self.assertEqual(indicator.type, 'indicator')
        self.assertEqual(indicator.created_by_ref, identity_id)

    def _check_indicator_time_features(self, indicator, object_time):
        timestamp = self._datetime_from_timestamp(object_time)
        self.assertEqual(indicator.created, timestamp)
        self.assertEqual(indicator.modified, timestamp)
        self.assertEqual(indicator.valid_from, timestamp)

    def _check_killchain(self, killchain, category):
        self.assertEqual(killchain['kill_chain_name'], 'misp-category')
        self.assertEqual(killchain['phase_name'], category)

    def _check_object_indicator_features(self, indicator, misp_object, identity_id, object_ref):
        self._check_indicator_features(indicator, identity_id, object_ref, misp_object['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, indicator.labels, to_ids=True)
        self._check_indicator_time_features(indicator, misp_object['timestamp'])

    def _check_object_labels(self, misp_object, labels, to_ids=None):
        if to_ids is not None:
            category_label, name_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{to_ids}"')
        else:
            category_label, name_label = labels
        self.assertEqual(category_label, f'misp:category="{misp_object["meta-category"]}"')
        self.assertEqual(name_label, f'misp:name="{misp_object["name"]}"')

    def _check_object_observable_features(self, observed_data, misp_object, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, misp_object['uuid'])
        self._check_object_labels(misp_object, observed_data.labels, to_ids=False)
        self._check_observable_time_features(observed_data, misp_object['timestamp'])

    def _check_object_vulnerability_features(self, vulnerability, misp_object, identity_id, object_ref):
        uuid = f"vulnerability--{misp_object['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(vulnerability.id, uuid)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_object_labels(misp_object, vulnerability.labels)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(vulnerability.modified, timestamp)
        cve, cvss, summary, created, published, references1, references2 = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(vulnerability.name, cve)
        self.assertEqual(vulnerability.description, summary)
        self.assertEqual(datetime.strftime(vulnerability.created, '%Y-%m-%dT%H:%M:%S'), created)
        cve_ref, url1, url2 = vulnerability.external_references
        self.assertEqual(cve_ref.source_name, 'cve')
        self.assertEqual(cve_ref.external_id, cve)
        self.assertEqual(url1.source_name, 'url')
        self.assertEqual(url1.url, references1)
        self.assertEqual(url2.source_name, 'url')
        self.assertEqual(url2.url, references2)
        self.assertEqual(vulnerability.x_misp_cvss_score, cvss)
        self.assertEqual(vulnerability.x_misp_published, published)

    def _check_observable_features(self, observed_data, identity_id, object_ref, object_uuid):
        uuid = f"observed-data--{object_uuid}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(observed_data.id, uuid)
        self.assertEqual(observed_data.type, 'observed-data')
        self.assertEqual(observed_data.created_by_ref, identity_id)
        self.assertEqual(observed_data.number_observed, 1)

    def _check_observable_time_features(self, observed_data, object_time):
        timestamp = self._datetime_from_timestamp(object_time)
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

    def _check_relationship_features(self, relationship, source_id, target_id, relationship_type, timestamp):
        self.assertEqual(relationship.type, 'relationship')
        self.assertEqual(relationship.source_ref, source_id)
        self.assertEqual(relationship.target_ref, target_id)
        self.assertEqual(relationship.relationship_type, relationship_type)
        self.assertEqual(relationship.created, timestamp)
        self.assertEqual(relationship.modified, timestamp)

    def _check_report_features(self, report, event, identity_id, timestamp):
        self.assertEqual(report.type, 'report')
        self.assertEqual(report.id, f"report--{event['uuid']}")
        self.assertEqual(report.created_by_ref, identity_id)
        self.assertEqual(report.labels, self._labels)
        self.assertEqual(report.name, event['info'])
        self.assertEqual(report.created, timestamp)
        self.assertEqual(report.modified, timestamp)
        return report.object_refs

    @staticmethod
    def _datetime_from_timestamp(timestamp):
        return datetime.utcfromtimestamp(int(timestamp))

    @staticmethod
    def _parse_AS_value(value):
        if value.startswith('AS'):
            return int(value[2:])
        return int(value)

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
        for attribute in event['Event']['Attribute']:
            attribute['to_ids'] = False

    @staticmethod
    def _remove_object_ids_flags(event):
        for misp_object in event['Event']['Object']:
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = False

    def _run_custom_attribute_tests(self, attribute, custom_object, object_ref, identity_id):
        attribute_type = attribute['type']
        category = attribute['category']
        custom_type = f"x-misp-attribute"
        self.assertEqual(custom_object.type, custom_type)
        self.assertEqual(object_ref, f"{custom_type}--{attribute['uuid']}")
        self.assertEqual(custom_object.id, object_ref)
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
        self.assertEqual(object_ref, f"{custom_type}--{misp_object['uuid']}")
        self.assertEqual(custom_object.id, object_ref)
        self.assertEqual(custom_object.created_by_ref, identity_id)
        self.assertEqual(custom_object.labels[0], f'misp:category="{category}"')
        self.assertEqual(custom_object.labels[1], f'misp:name="{name}"')
        self.assertEqual(custom_object.x_misp_name, name)
        self.assertEqual(custom_object.x_misp_meta_category, category)
        if misp_object.get('comment'):
            self.assertEqual(custom_object.x_misp_comment, misp_object['comment'])
        for custom_attribute, attribute in zip(custom_object.x_misp_attributes, misp_object['Attribute']):
            for feature in ('type', 'object_relation', 'value'):
                self.assertEqual(custom_attribute[feature], attribute[feature])
            for feature in ('category', 'comment', 'to_ids', 'uuid'):
                if attribute.get(feature):
                    self.assertEqual(custom_attribute[feature], attribute[feature])

    @staticmethod
    def _sanitize_registry_key_value(value: str) -> str:
        sanitized = value.strip().replace('\\', '\\\\')
        if '%' not in sanitized or '\\\\%' in sanitized:
            return sanitized
        if '\\%' in sanitized:
            return sanitized.replace('\\%', '\\\\%')
        return sanitized.replace('%', '\\\\%')
