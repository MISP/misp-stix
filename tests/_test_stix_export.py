#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import misp_stix_converter
import os
import unittest
from base64 import b64encode
from collections import defaultdict
from datetime import datetime, timezone
from misp_stix_converter.misp2stix.exportparser import MISPtoSTIXParser
from pathlib import Path
from pymisp import MISPAttribute
from shutil import copyfile
from stix.core import STIXPackage
from stix2patterns.validator import validate
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid5, UUID
from ._test_stix import PLANTED_TEMPLATE, TestSTIX

_DEFAULT_ORGNAME = 'MISP'
_ATTRIBUTE_EXCLUSION_LIST = ('disable_correlation', 'to_ids')
_MISP_OBJECT_EXCLUSION_LIST = (
    'distribution', 'sharing_group_id', 'template_uuid', 'template_version'
)
# What an output file the caller never asked to replace holds, and the parsing
# a conversion goes through on the way to writing one
_PRESERVED_OUTPUT = 'IMPORTANT PRE-EXISTING CONTENT'
_parse_json_file = MISPtoSTIXParser.parse_json_file

# Object relations reaching a pattern property-name position, paired with the
# pattern segment each one must produce. An unquoted metacharacter segment
# either breaks the pattern - the object is then reported instead of converted
# - or, for a dotted relation, silently turns one property into a path. The
# last pair is the benign control: a relation needing no quotes keeps the bare
# segment it always had. Segments are spelled out rather than computed, so the
# expectations do not restate the escaping they guard.
_PATTERN_SEGMENT_RELATIONS = (
    ("rel' OR file:name = 'x", r"'x_misp_rel\' OR file:name = \'x'"),
    ('rel]', "'x_misp_rel]'"),
    ('rel=1', "'x_misp_rel=1'"),
    ('weird relation', "'x_misp_weird relation'"),
    ("x'", r"'x_misp_x\''"),
    ('a.b', "'x_misp_a.b'"),
    ('rel-with-dash', 'x_misp_rel_with_dash')
)


class TestCollectionSTIXExport(unittest.TestCase):
    # The 2 scratch locations the defaults used to resolve to: the package
    # directory, and its parent - `site-packages` on an install, the
    # repository root in a source checkout
    _package_path = Path(misp_stix_converter.__file__).parent
    _package_tree_scratch = (_package_path / 'tmp', _package_path.parent / 'tmp')

    def setUp(self):
        self._current_path = Path(__file__).parent

    def tearDown(self):
        for filename in self._current_path.glob('test_*_collection*.json.out'):
            os.remove(filename)

    def _check_created_output_directory(self, conversion, *input_files, **kwargs):
        # An output directory the caller names but has not created yet is a
        # request, not a mistake: it is created instead of raising at write
        # time - whether it is named as the directory itself or as the parent
        # of an output file name
        with TemporaryDirectory() as tmp_dir:
            copies = self._copy_inputs(tmp_dir, *input_files)
            output_dir = Path(tmp_dir) / 'missing' / 'output'
            results = conversion(
                *copies, single_output=True, output_dir=output_dir, **kwargs
            )
            self.assertEqual(results['success'], 1)
            self.assertTrue(output_dir.is_dir())
            self.assertEqual(results['results'][0].parent, output_dir)
            output_name = Path(tmp_dir) / 'missing too' / 'collection.out'
            results = conversion(
                *copies, single_output=True, output_name=output_name, **kwargs
            )
            self.assertEqual(results['success'], 1)
            self.assertEqual(results['results'][0], output_name)
            self.assertTrue(output_name.is_file())

    def _check_default_single_output(self, conversion, *input_files, **kwargs):
        # A collection export called with its documented defaults writes next
        # to the input files, under a name every filesystem accepts, and the
        # fragments a streamed assembly wrote are gone by the time it returns.
        # The package tree is left exactly as it was: it is not an output or a
        # scratch location
        package_tree = self._package_tree_content()
        with TemporaryDirectory() as tmp_dir:
            copies = self._copy_inputs(tmp_dir, *input_files)
            results = conversion(*copies, single_output=True, **kwargs)
            self.assertEqual(results['success'], 1)
            output = results['results'][0]
            self.assertEqual(output.parent, Path(tmp_dir).resolve())
            self.assertNotIn(':', output.name)
            self.assertEqual(
                sorted(path.name for path in Path(tmp_dir).iterdir()),
                sorted([copy.name for copy in copies] + [output.name])
            )
        self.assertEqual(self._package_tree_content(), package_tree)

    def _check_destination_appearing_mid_conversion(
            self, conversion, *input_files, **kwargs):
        # The check taken before the work cannot see a destination that appears
        # while the conversion runs: the output file is created rather than
        # replaced, so the collision is still refused instead of silently
        # clobbered at the end
        appeared = []

        def _create_the_destination(parser, filename):
            if not appeared:
                appeared.append(filename)
                output_name.write_text(_PRESERVED_OUTPUT, encoding='utf-8')
            return _parse_json_file(parser, filename)

        with TemporaryDirectory() as tmp_dir:
            copies = self._copy_inputs(tmp_dir, *input_files)
            output_name = Path(tmp_dir) / 'previous.out'
            with patch.object(
                    MISPtoSTIXParser, 'parse_json_file',
                    _create_the_destination):
                with self.assertRaises(FileExistsError) as context:
                    conversion(*copies, output_name=output_name, **kwargs)
            self.assertIn(str(output_name), str(context.exception))
            self.assertEqual(
                output_name.read_text(encoding='utf-8'), _PRESERVED_OUTPUT
            )
            self.assertEqual(
                sorted(path.name for path in Path(tmp_dir).iterdir()),
                sorted([copy.name for copy in copies] + [output_name.name])
            )

    def _check_interrupted_write_keeps_the_destination(
            self, conversion, *input_files, interrupt=None, **kwargs):
        # A conversion killed while it writes - `KeyboardInterrupt` is what a
        # signal raises, and the one thing the per-input `except Exception`
        # does not catch - leaves the file it was replacing exactly as it was,
        # and no half-written scratch file next to it. The kill lands on the
        # second input file's parsing, by the time the first one's content is
        # written; `interrupt` names an (owner, attribute) pair instead, for a
        # path whose writing all happens after the last input file is parsed
        parsed = []

        def _interrupt_the_second_input(parser, filename):
            parsed.append(filename)
            if len(parsed) > 1:
                raise KeyboardInterrupt('Killed while writing')
            return _parse_json_file(parser, filename)

        def _interrupt_now(*args, **kwargs):
            raise KeyboardInterrupt('Killed while writing')

        killed = (
            patch.object(
                MISPtoSTIXParser, 'parse_json_file',
                _interrupt_the_second_input
            ) if interrupt is None
            else patch.object(*interrupt, _interrupt_now)
        )
        with TemporaryDirectory() as tmp_dir:
            copies = self._copy_inputs(tmp_dir, *input_files)
            output_name = self._preserved_output(tmp_dir)
            with killed:
                with self.assertRaises(KeyboardInterrupt):
                    conversion(
                        *copies, output_name=output_name, overwrite=True,
                        **kwargs
                    )
            self.assertEqual(
                output_name.read_text(encoding='utf-8'), _PRESERVED_OUTPUT
            )
            self.assertEqual(
                sorted(path.name for path in Path(tmp_dir).iterdir()),
                sorted([copy.name for copy in copies] + [output_name.name])
            )

    def _check_output_file_mode(self, conversion, *input_files, **kwargs):
        # What a conversion writes carries whatever the events do, TLP:AMBER
        # and TLP:RED material included: a new output file is readable by its
        # owner alone, whatever the process umask would have allowed
        umask = os.umask(0)
        try:
            with TemporaryDirectory() as tmp_dir:
                copies = self._copy_inputs(tmp_dir, *input_files)
                results = conversion(*copies, **kwargs)
                self.assertEqual(results['success'], 1)
                for output in results['results']:
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        finally:
            os.umask(umask)

    def _check_overwrite_policy(
            self, conversion, *input_files, recorded: bool = False, **kwargs):
        # An **Output Location** already holding a file is only written when
        # the caller asked for it: the refusal follows the error channel the
        # path has for a write it cannot do - recorded per input where the
        # write sits inside a `try`, raised where it does not - and names the
        # file it did not touch either way
        with TemporaryDirectory() as tmp_dir:
            copies = self._copy_inputs(tmp_dir, *input_files)
            output_name = self._preserved_output(tmp_dir)
            arguments = {'output_name': output_name, **kwargs}
            if recorded:
                results = conversion(*copies, **arguments)
                self.assertNotIn('success', results)
                message = results['fails'][0]
            else:
                with self.assertRaises(FileExistsError) as context:
                    conversion(*copies, **arguments)
                message = str(context.exception)
            self.assertIn(str(output_name), message)
            self.assertIn('overwrite', message)
            self.assertEqual(
                output_name.read_text(encoding='utf-8'), _PRESERVED_OUTPUT
            )
            results = conversion(*copies, overwrite=True, **arguments)
            self.assertEqual(results['success'], 1)
            self.assertEqual(results['results'][0], output_name)
            self.assertNotEqual(
                output_name.read_text(encoding='utf-8'), _PRESERVED_OUTPUT
            )

    def _collection_files(self, name: str) -> list:
        return [self._current_path / f'{name}_{n}.json' for n in (1, 2)]

    def _copy_inputs(self, tmp_dir: str, *input_files: Path) -> list:
        return [
            Path(copyfile(input_file, Path(tmp_dir) / input_file.name))
            for input_file in input_files
        ]

    def _package_tree_content(self) -> tuple:
        # `None` for a location that does not exist - the state a default
        # writing there would change first
        return tuple(
            sorted(path.name for path in scratch.iterdir())
            if scratch.is_dir() else None
            for scratch in self._package_tree_scratch
        )

    def _preserved_output(self, tmp_dir: str) -> Path:
        output_name = Path(tmp_dir) / 'previous.out'
        output_name.write_text(_PRESERVED_OUTPUT, encoding='utf-8')
        return output_name


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
    def _export_event_with_invalid_hash(self, version: str) -> dict:
        # A `to_ids` file object with an invalid hash is recorded as an error
        # and the hash is dropped: the partial failure a result dict has to
        # report.
        from misp_stix_converter import misp_to_stix2
        from tempfile import TemporaryDirectory
        from .test_events import get_event_with_file_object
        event = get_event_with_file_object()
        event['Event']['Object'][0]['Attribute'].append(
            {
                'type': 'tlsh', 'object_relation': 'tlsh',
                'value': 'T1' + 'a1b2c3d4e5' * 7, 'to_ids': True
            }
        )
        with TemporaryDirectory() as tmp_dir:
            filename = Path(tmp_dir) / 'event_with_invalid_hash.json'
            with open(filename, 'wt', encoding='utf-8') as f:
                json.dump(event, f)
            return misp_to_stix2(filename, version=version)

    def _check_stix2_results_export(self, to_test_file, reference_file):
        with open(to_test_file, 'rt', encoding='utf-8') as f:
            to_test = json.load(f)
        with open(reference_file, 'rt', encoding='utf-8') as f:
            reference = json.load(f)
        reference_objects = reference['objects']
        objects_to_test = to_test['objects']
        self.assertEqual(len(reference_objects), len(objects_to_test))
        for reference_object, object_to_test in zip(reference_objects, objects_to_test):
            if reference_object['type'] == 'relationship':
                self.assertEqual(reference_object['source_ref'], object_to_test['source_ref'])
                self.assertEqual(reference_object['target_ref'], object_to_test['target_ref'])
                self.assertEqual(
                    reference_object['relationship_type'], object_to_test['relationship_type']
                )
                continue
            if reference_object['type'] in ('grouping', 'report'):
                for key, value in reference_object.items():
                    if key == 'object_refs':
                        for index, object_ref in enumerate(value):
                            if object_ref.startswith('relationship--'):
                                self.assertTrue(
                                    object_to_test[key][index].startswith('relationship--')
                                )
                                continue
                            self.assertEqual(object_ref, object_to_test[key][index])
                        continue
                    self.assertEqual(value, object_to_test[key])
                continue
            self.assertEqual(reference_object, object_to_test)


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

    def _add_metacharacter_relation(self, event, relation, value):
        misp_object = event['Event']['Object'][0]
        misp_object['Attribute'].append(
            {
                'type': 'text', 'object_relation': relation,
                'value': value, 'to_ids': True
            }
        )
        return misp_object

    def _get_indicators(self):
        return [
            stix_object for stix_object in self.parser.stix_objects
            if stix_object['type'] == 'indicator'
        ]

    def _object_errors(self, misp_object):
        return [
            error for errors in self.parser.errors.values()
            for error in errors if misp_object['uuid'] in error
        ]

    def _check_account_indicator_objects(self, misp_objects, patterns):
        gitlab_object, telegram_object = misp_objects
        gitlab_pattern, telegram_pattern = patterns
        gitlab_id = gitlab_object.attributes[0].value
        account_type, user_id = gitlab_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'gitlab'")
        self.assertEqual(user_id, f"user-account:user_id = '{gitlab_id}'")
        telegram_id = telegram_object.attributes[0].value
        account_type, user_id = telegram_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'telegram'")
        self.assertEqual(user_id, f"user-account:user_id = '{telegram_id}'")

    def _check_account_with_attachment_indicator_objects(self, misp_objects, patterns):
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook_pattern, github_pattern, parler_pattern, reddit_pattern, twitter_pattern = patterns
        account_id = facebook_account.attributes[0].value
        account_type, user_id = facebook_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'facebook'")
        self.assertEqual(user_id, f"user-account:user_id = '{account_id}'")
        github_id = github_user.attributes[0].value
        account_type, user_id = github_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'github'")
        self.assertEqual(user_id, f"user-account:user_id = '{github_id}'")
        parler_id = parler_account.attributes[0].value
        account_type, user_id = parler_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'parler'")
        self.assertEqual(user_id, f"user-account:user_id = '{parler_id}'")
        reddit_id = reddit_account.attributes[0].value
        account_type, user_id = reddit_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'reddit'")
        self.assertEqual(user_id, f"user-account:user_id = '{reddit_id}'")
        _id = twitter_account.attributes[0].value
        account_type, user_id = twitter_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'twitter'")
        self.assertEqual(user_id, f"user-account:user_id = '{_id}'")

    def _check_attack_pattern_meta_fields(self, stix_object, meta):
        external_ref, *external_refs = stix_object.external_references
        self.assertEqual(external_ref.external_id, meta['external_id'])
        if meta.get('refs') is not None:
            for external_ref, ref in zip(external_refs, meta['refs']):
                self.assertEqual(external_ref.url, ref)
        for killchain_phase, killchain in zip(stix_object.kill_chain_phases, meta['kill_chain']):
            killchain_name, *_, phase_name = killchain.split(':')
            self.assertEqual(killchain_phase.kill_chain_name, killchain_name)
            self.assertEqual(killchain_phase.phase_name, phase_name)

    def _check_attack_pattern_object(self, attack_pattern, misp_object, identity_id):
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self.assertEqual(attack_pattern.created_by_ref, identity_id)
        self._check_killchain(attack_pattern.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, attack_pattern.labels)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(attack_pattern.created, timestamp)
        self.assertEqual(attack_pattern.modified, timestamp)
        id_, name, summary, weakness1, weakness2, prerequisite, solution = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(attack_pattern.name, name)
        self.assertEqual(attack_pattern.description, summary)
        self._check_external_reference(
            attack_pattern.external_references[0], 'capec', f'CAPEC-{id_}'
        )
        self.assertEqual(attack_pattern.x_misp_related_weakness, [weakness1, weakness2])
        self.assertEqual(attack_pattern.x_misp_prerequisites, prerequisite)
        self.assertEqual(attack_pattern.x_misp_solutions, solution)

    def _check_attribute_campaign_features(self, campaign, attribute, identity_id, object_ref):
        self._assert_multiple_equal(
            campaign.id, f"campaign--{attribute['uuid']}", object_ref
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
        type_label, category_label = labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')

    def _check_attribute_observable_features(self, observed_data, attribute, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, attribute['uuid'])
        self._check_attribute_labels(attribute, observed_data.labels)
        self._check_observable_time_features(observed_data, attribute['timestamp'])

    def _check_attribute_vulnerability_features(self, vulnerability, attribute, identity_id, object_ref):
        self._assert_multiple_equal(
            vulnerability.id, f"vulnerability--{attribute['uuid']}", object_ref
        )
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, vulnerability.labels)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(vulnerability.created, timestamp)
        self.assertEqual(vulnerability.modified, timestamp)

    def _check_campaign_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.aliases, meta['synonyms'])
        self.assertEqual(
            stix_object.last_seen, self._datetime_from_str(meta['last_seen'])
        )
        self.assertEqual(stix_object.objective, meta['objective'])

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
                    course_of_action, f"x_misp_{attribute['object_relation']}"
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
            employee.id, employee_ref, f"identity--{misp_object['uuid']}"
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

    def _check_event_with_escaped_characters(
            self, indicators, initial_attributes, attributes, misp_objects):
        (invalid_AS, _, invalid_domain, invalid_domain_ip, *_, invalid_md5,
         _, invalid_hostname, invalid_hostname_port, invalid_http_method,
         invalid_ip, invalid_ip_port, _, _, _, invalid_port, _, _,
         invalid_size, _, _, invalid_x509_md5) = initial_attributes
        (_, _, domain_ip, _, _, ip_port, _, network_connection,
         network_socket, *_) = misp_objects
        validation_errors = self.parser.warnings.get('misp event', [])
        self.assertEqual(len(validation_errors), 17)
        connection_src_ip, connection_dst_ip = network_connection['Attribute']
        error_messages = list(
            self._check_validation_errors(
                validation_errors,
                [invalid_AS], [invalid_domain], [invalid_domain_ip],
                [invalid_md5], [invalid_hostname], [invalid_hostname_port],
                [invalid_http_method], [invalid_ip], [invalid_ip_port],
                [invalid_port], [invalid_size], [invalid_x509_md5],
                [domain_ip['Attribute'][0], domain_ip['uuid'], domain_ip['name']],
                [ip_port['Attribute'][2], ip_port['uuid'], ip_port['name']],
                [connection_src_ip, network_connection['uuid'], network_connection['name']],
                [connection_dst_ip, network_connection['uuid'], network_connection['name']],
                [network_socket['Attribute'][1], network_socket['uuid'], network_socket['name']]
            )
        )
        if error_messages:
            dont, attr, messages = (
                ("s don't ", 'attributes', 'messages')
                if len(error_messages) > 1 else
                (" doesn't ", 'attribute', 'message')
            )
            message = (
                f'Validation error message{dont} properly describe the {attr} '
                f'that failed validation in the following {messages}'
            )
            self.fail(self._formatMessage('\n'.join(['\n', *error_messages]), message))
        misp_objects = self.parser._misp_event.objects
        (attachment, email, email_attachment, email_body, email_dst,
         email_header, email_reply_to, email_src, email_subject,
         email_x_mailer, filename, filename_md5, mac_address, malware_sample,
         mutex, regkey, regkey_value, url, user_agent) = attributes
        (asn, credential, domain_ip, email_object, file_object, ip_port,
         mutex_object, _, network_socket, pe, _, process, registry_key,
         url_object, user_account, x509) = misp_objects
        (attachment_indicator, email_indicator, email_attachment_indicator,
         email_body_indicator, email_dst_indicator, email_header_indicator,
         email_reply_to_indicator, email_src_indicator, email_subject_indicator,
         email_x_mailer_indicator, filename_indicator, filename_md5_indicator,
         mac_address_indicator, malware_sample_indicator, mutex_indicator,
         regkey_indicator, regkey_value_indicator, url_indicator,
         user_agent_indicator, asn_indicator, credential_indicator,
         email_object_indicator, file_indicator, ip_port_indicator,
         mutex_object_indicator, network_socket_indicator, process_indicator,
         registry_key_indicator, url_object_indicator, user_account_indicator,
         x509_indicator, pe_indicator) = indicators
        self.assertIn(attachment.uuid, attachment_indicator.id)
        self.assertIn(email.uuid, email_indicator.id)
        self.assertIn(email_attachment.uuid, email_attachment_indicator.id)
        self.assertIn(email_body.uuid, email_body_indicator.id)
        self.assertIn(email_dst.uuid, email_dst_indicator.id)
        self.assertIn(email_header.uuid, email_header_indicator.id)
        self.assertIn(email_reply_to.uuid, email_reply_to_indicator.id)
        self.assertIn(email_src.uuid, email_src_indicator.id)
        self.assertIn(email_subject.uuid, email_subject_indicator.id)
        self.assertIn(email_x_mailer.uuid, email_x_mailer_indicator.id)
        self.assertIn(filename.uuid, filename_indicator.id)
        self.assertIn(filename_md5.uuid, filename_md5_indicator.id)
        self.assertIn(mac_address.uuid, mac_address_indicator.id)
        self.assertIn(malware_sample.uuid, malware_sample_indicator.id)
        self.assertIn(mutex.uuid, mutex_indicator.id)
        self.assertIn(regkey.uuid, regkey_indicator.id)
        self.assertIn(regkey_value.uuid, regkey_value_indicator.id)
        self.assertIn(url.uuid, url_indicator.id)
        self.assertIn(user_agent.uuid, user_agent_indicator.id)
        self.assertIn(asn.uuid, asn_indicator.id)
        self.assertIn(credential.uuid, credential_indicator.id)
        self.assertIn(email_object.uuid, email_object_indicator.id)
        self.assertIn(file_object.uuid, file_indicator.id)
        self.assertIn(ip_port.uuid, ip_port_indicator.id)
        self.assertIn(mutex_object.uuid, mutex_object_indicator.id)
        self.assertIn(network_socket.uuid, network_socket_indicator.id)
        self.assertIn(process.uuid, process_indicator.id)
        self.assertIn(registry_key.uuid, registry_key_indicator.id)
        self.assertIn(url_object.uuid, url_object_indicator.id)
        self.assertIn(user_account.uuid, user_account_indicator.id)
        self.assertIn(x509.uuid, x509_indicator.id)
        self.assertIn(pe.uuid, pe_indicator.id)

    def _check_external_reference(self, reference, source_name, value):
        self.assertEqual(reference.source_name, source_name)
        self.assertEqual(reference.external_id, value)

    def _test_attributes_collection_with_meta_less_galaxies(self, attributes):
        self.parser.parse_misp_attributes(attributes)
        self.assertIsNotNone(self.parser.bundle)
        produced = {
            stix_object.id.split('--')[-1]
            for stix_object in self.parser.stix_objects
        }
        for galaxy in attributes['Galaxy']:
            for cluster in galaxy['GalaxyCluster']:
                self.assertNotIn('meta', cluster)
                self.assertIn(
                    cluster['uuid'], produced,
                    f"No STIX object produced for the meta-less "
                    f"{galaxy['type']} Galaxy Cluster {cluster['uuid']}"
                )

    def _check_galaxy_features(self, stix_object, galaxy, timestamp):
        cluster = galaxy['GalaxyCluster'][0]
        self.assertEqual(stix_object.id, f"{stix_object.type}--{cluster['uuid']}")
        self.assertEqual(stix_object.created, timestamp)
        self.assertEqual(stix_object.modified, timestamp)
        self.assertEqual(
            stix_object.name,
            cluster['value'].split(' - ')[0] if
            cluster['type'].startswith('mitre-') else cluster['value']
        )
        if cluster.get('description'):
            self.assertEqual(stix_object.description, cluster['description'])
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
        aliases = [
            synonym for synonym in meta.get('synonyms', [])
            if synonym != stix_object.name
        ]
        if aliases:
            self.assertEqual(stix_object.aliases, aliases)
        if meta.get('external_id') is not None:
            external_ref, *external_refs = stix_object.external_references
            self.assertEqual(external_ref.external_id, meta['external_id'])
            for external_ref, ref in zip(external_refs, meta['refs']):
                self.assertEqual(external_ref.url, ref)
        for field in ('goals', 'primary_motivation', 'resource_level'):
            if meta.get(field) is not None:
                self.assertEqual(getattr(stix_object, field), meta[field])

    def _check_intrusion_set_object(self, intrusion_set, misp_object, identity_id):
        self.assertEqual(intrusion_set.type, 'intrusion-set')
        self.assertEqual(intrusion_set.created_by_ref, identity_id)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(intrusion_set.created, timestamp)
        self.assertEqual(intrusion_set.modified, timestamp)
        name, description, alias, *goals, level, primary, secondary, first_seen, last_seen = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(intrusion_set.name, name)
        self.assertEqual(intrusion_set.description, description)
        self.assertEqual(intrusion_set.aliases, [alias])
        self.assertTrue(
            all(goal in intrusion_set.goals for goal in goals) and
            len(intrusion_set.goals) == len(goals)
        )
        self.assertEqual(intrusion_set.resource_level, level)
        self.assertEqual(intrusion_set.primary_motivation, primary)
        self.assertEqual(intrusion_set.secondary_motivations, [secondary])
        if isinstance(first_seen, str):
            first_seen = self._datetime_from_str(first_seen)
        self.assertEqual(intrusion_set.first_seen, first_seen)
        if isinstance(last_seen, str):
            last_seen = self._datetime_from_str(last_seen)
        self.assertEqual(intrusion_set.last_seen, last_seen)

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
        aliases = [
            synonym for synonym in meta.get('synonyms', [])
            if synonym != stix_object.name
        ]
        if aliases:
            if hasattr(stix_object, 'aliases'):
                self.assertEqual(stix_object.aliases, meta['synonyms'])
            else:
                self.assertEqual(stix_object.x_misp_synonyms, meta['synonyms'])
        # Regular Malware Galaxy Cluster fields
        if meta.get('external_id') is not None:
            external_ref, *external_refs = stix_object.external_references
            self.assertEqual(external_ref.external_id, meta['external_id'])
            for external_ref, ref in zip(external_refs, meta['refs']):
                self.assertEqual(external_ref.url, ref)
        if meta.get('mitre_platform') is not None:
            self.assertEqual(
                stix_object.x_misp_mitre_platforms,
                meta['mitre_platforms']
            )

    def _check_object_indicator_features(self, indicator, misp_object, identity_id, object_ref):
        self._check_indicator_features(indicator, identity_id, object_ref, misp_object['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, indicator.labels)
        self._check_indicator_time_features(indicator, misp_object['timestamp'])

    def _check_object_labels(self, misp_object, labels):
        name_label, category_label = labels
        self.assertEqual(name_label, f'misp:name="{misp_object["name"]}"')
        self.assertEqual(category_label, f'misp:meta-category="{misp_object["meta-category"]}"')

    def _check_object_observable_features(self, observed_data, misp_object, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, misp_object['uuid'])
        self._check_object_labels(misp_object, observed_data.labels)
        self._check_observable_time_features(observed_data, misp_object['timestamp'])

    def _check_object_vulnerability_features(self, vulnerability, misp_object, identity_id, object_ref):
        self._assert_multiple_equal(
            vulnerability.id, f"vulnerability--{misp_object['uuid']}", object_ref
        )
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_object_labels(misp_object, vulnerability.labels)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(vulnerability.modified, timestamp)
        cve, cvss, summary, created, published, references1, references2 = (
            attribute.value for attribute in misp_object.attributes
        )
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

    def _check_pattern_metacharacter_relations(self, event_getter, prefix):
        value = 'metacharacter value'
        for relation, segment in _PATTERN_SEGMENT_RELATIONS:
            with self.subTest(object_relation=relation):
                self.setUp()
                event = event_getter()
                self._add_object_ids_flag(event['Event'])
                misp_object = self._add_metacharacter_relation(
                    event, relation, value
                )
                self.parser.parse_misp_event(event['Event'])
                self.assertEqual(self._object_errors(misp_object), [])
                indicators = self._get_indicators()
                self.assertEqual(len(indicators), 1)
                self.assertIn(
                    f"{prefix}:{segment} = '{value}'", indicators[0].pattern
                )
                self.assertTrue(
                    validate(
                        indicators[0].pattern,
                        stix_version=self.parser._version
                    )
                )

    def _check_unquotable_pattern_reported(self, event_getter, name):
        # The quoting under test is what keeps a metacharacter relation out of
        # the property-name position; with it neutralised the pattern fails to
        # parse, and the object must then be *reported* and converted as a
        # custom object rather than vanishing from the export.
        event = event_getter()
        self._add_object_ids_flag(event['Event'])
        misp_object = self._add_metacharacter_relation(event, 'rel]', 'V')
        with patch.object(
                self.parser, '_quote_custom_property',
                lambda relation: f'x_misp_{relation}'):
            self.parser.parse_misp_event(event['Event'])
        self.assertEqual(self._get_indicators(), [])
        self.assertIn(
            'x-misp-object',
            [stix_object['type'] for stix_object in self.parser.stix_objects]
        )
        object_errors = self._object_errors(misp_object)
        self.assertEqual(len(object_errors), 1)
        self.assertTrue(
            object_errors[0].startswith(
                f"Error with the {name} object "
                f"(uuid: {misp_object['uuid']}):"
            )
        )

    def _check_pe_and_section_observable(self, extension, pe, section):
        (_type, compilation, entrypoint, original, internal, desc, version,
         lang, prod_name, prod_version, company, _copyright, sections, imphash,
         impfuzzy) = (attribute['value'] for attribute in pe['Attribute'])
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
        self.assertEqual(extension.x_misp_legal_copyright, _copyright)
        self.assertEqual(extension.x_misp_original_filename, original)
        self.assertEqual(extension.x_misp_product_name, prod_name)
        self.assertEqual(extension.x_misp_product_version, prod_version)
        name, size, entropy, md5, sha1, sha256, sha512, ssdeep = (
            attribute['value'] for attribute in section['Attribute']
        )
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
        _type, _, _, _original, _internal, *_, _imphash, _impfuzzy = (
            attribute['value'] for attribute in pe['Attribute']
        )
        (imphash_, type_, original_, internal_, impfuzzy_,
         name_, md5_, sha1_, sha256_, sha512_, ssdeep_) = pattern
        prefix = "file:extensions.'windows-pebinary-ext'"
        self.assertEqual(imphash_, f"{prefix}.imphash = '{_imphash}'")
        self.assertEqual(type_, f"{prefix}.pe_type = '{_type}'")
        self.assertEqual(original_, f"{prefix}.x_misp_original_filename = '{_original}'")
        self.assertEqual(internal_, f"{prefix}.x_misp_internal_filename = '{_internal}'")
        self.assertEqual(impfuzzy_, f"{prefix}.x_misp_impfuzzy = '{_impfuzzy}'")
        _name, *_, _md5, _sha1, _sha256, _sha512, _ssdeep = (
            attribute['value'] for attribute in section['Attribute']
        )
        prefix = f"{prefix}.sections[0]"
        self.assertEqual(name_, f"{prefix}.name = '{_name}'")
        self.assertEqual(md5_, f"{prefix}.hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"{prefix}.hashes.'SHA-1' = '{_sha1}'")
        self.assertEqual(sha256_, f"{prefix}.hashes.'SHA-256' = '{_sha256}'")
        self.assertEqual(sha512_, f"{prefix}.hashes.'SHA-512' = '{_sha512}'")
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

    def _check_sighting_features(
            self, stix_sighting, misp_sighting, object_id, identity_id, observed_data_id=None):
        self.assertEqual(stix_sighting.type, 'sighting')
        self.assertEqual(stix_sighting.id, f"sighting--{misp_sighting['uuid']}")
        self._assert_multiple_equal(
            stix_sighting.created, stix_sighting.modified,
            self._datetime_from_timestamp(misp_sighting['date_sighting'])
        )
        self.assertEqual(stix_sighting.sighting_of_ref, object_id)
        self.assertEqual(stix_sighting.where_sighted_refs, [identity_id])
        if observed_data_id is not None:
            self.assertEqual(stix_sighting.observed_data_refs, [observed_data_id])

    def _check_threat_actor_meta_fields(self, stix_object, meta):
        self.assertEqual(stix_object.aliases, meta['synonyms'])
        for field in ('primary_motivation', 'resource_level', 'roles'):
            if field in meta:
                self.assertEqual(getattr(stix_object, field), meta[field])

    def _check_tool_meta_fields(self, stix_object, meta):
        aliases = [
            synonym for synonym in meta.get('synonyms', [])
            if synonym != stix_object.name
        ]
        if aliases:
            if hasattr(stix_object, 'aliases'):
                self.assertEqual(stix_object.aliases, aliases)
            else:
                self.assertEqual(stix_object.x_misp_synonyms, aliases)
        if meta.get('external_id') is not None:
            external_id, *external_refs = stix_object.external_references
            self.assertEqual(external_id.external_id, meta['external_id'])
        else:
            external_refs = stix_object.external_references
        for external_ref, ref in zip(external_refs, meta['refs']):
            self.assertEqual(external_ref.url, ref)
        if meta.get('mitre_platforms') is not None:
            self.assertEqual(
                stix_object.x_misp_mitre_platforms, meta['mitre_platforms']
            )
        if meta.get('tool_version') is not None:
            self.assertEqual(stix_object.tool_version, meta['tool_version'])
        if meta.get('kill_chain') is not None:
            for killchain_phase, killchain in zip(stix_object.kill_chain_phases, meta['kill_chain']):
                killchain_name, *_, phase_name = killchain.split(':')
                self.assertEqual(killchain_phase.kill_chain_name, killchain_name)
                self.assertEqual(killchain_phase.phase_name, phase_name)

    def _check_validation_errors(self, error_messages, *fields_to_check):
        for values in fields_to_check:
            attribute, *object_fields = values
            to_check = (attribute['uuid'], attribute['value'], *object_fields)
            for error_message in error_messages:
                if all(field in error_message for field in to_check):
                    break
            else:
                message = f"Attribute with UUID ({attribute['uuid']}) and value ({attribute['value']})"
                if object_fields:
                    object_uuid, object_name = object_fields
                    message += f' within {object_name} MISP object with UUID ({object_uuid})'
                yield message

    def _check_vulnerability_meta_fields(self, stix_object, meta):
        if meta.get('aliases') is not None:
            self.assertEqual(
                stix_object.external_references[0],
                {
                    'source_name': 'cve',
                    'external_id': meta['aliases'][0]
                }
            )
        if meta.get('external_id') is not None:
            self.assertEqual(
                stix_object.external_references[0],
                {
                    'source_name': 'cve',
                    'external_id': meta['external_id']
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
    def _populate_attribute(attribute, exclude=('disable_correlation')):
        if isinstance(attribute, MISPAttribute):
            attribute = json.loads(attribute.to_json())
        for key, value in attribute.items():
            if key not in exclude:
                yield key, value

    def _populate_object(self, misp_object, exclude=_MISP_OBJECT_EXCLUSION_LIST):
        for key, value in json.loads(misp_object.to_json()).items():
            if key == 'Attribute':
                yield key, [dict(self._populate_attribute(attribute)) for attribute in value]
                continue
            if key not in exclude:
                yield key, value

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
        custom_type = 'x-misp-attribute'
        self.assertEqual(custom_object.type, custom_type)
        self._assert_multiple_equal(
            custom_object.id,
            f"{custom_type}--{attribute['uuid']}",
            object_ref
        )
        self.assertEqual(custom_object.created_by_ref, identity_id)
        self.assertEqual(custom_object.labels[0], f'misp:type="{attribute_type}"')
        self.assertEqual(custom_object.labels[1], f'misp:category="{category}"')
        self.assertEqual(custom_object.x_misp_type, attribute_type)
        self.assertEqual(custom_object.x_misp_category, category)
        if attribute.get('comment'):
            self.assertEqual(custom_object.x_misp_comment, attribute['comment'])
        self.assertEqual(custom_object.x_misp_value, attribute['value'])

    def _run_invalid_object_name_tests(self, event, rejected_name):
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        custom_object = self.parser.stix_objects[-1]
        # The name never reached template resolution: the object is generic,
        # and carries no field that could only come from a template file.
        self.assertEqual(misp_object.name, 'unknown-template')
        self.assertFalse(misp_object._known_template)
        self.assertNotEqual(
            getattr(misp_object, 'meta-category', None),
            PLANTED_TEMPLATE['meta-category']
        )
        self.assertEqual(custom_object.x_misp_name, 'unknown-template')
        self.assertEqual(
            custom_object.labels[0], 'misp:name="unknown-template"'
        )
        # Nothing is lost: the rejected name is kept as data.
        self.assertIn(rejected_name, custom_object.x_misp_comment)
        self.assertIn(event['uuid'], self.parser.warnings)
        name_warnings = [
            warning for warning in self.parser.warnings[event['uuid']]
            if 'Invalid MISP object template name' in warning
        ]
        self.assertEqual(len(name_warnings), 1)
        self.assertIn(rejected_name, name_warnings[0])

    def _check_invalid_object_name_collection(self, parser, rejected_name):
        custom_object = parser.stix_objects[-1]
        self.assertEqual(custom_object.x_misp_name, 'unknown-template')
        self.assertIn(rejected_name, custom_object.x_misp_comment)
        name_warnings = [
            warning for warning in parser.warnings['objects collection']
            if 'Invalid MISP object template name' in warning
        ]
        self.assertEqual(len(name_warnings), 1)
        self.assertIn(rejected_name, name_warnings[0])

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

    def _sanitise_pattern_value(self, value):
        sanitised = self._sanitise_registry_key_value(value)
        return sanitised.replace("'", "\\'").replace('"', '\\\\"')

    def _sanitise_registry_key_value(self, value: str) -> str:
        sanitised = self._sanitise_value(value.strip()).replace('\\', '\\\\')
        if '%' not in sanitised or '\\\\%' in sanitised:
            return sanitised
        if '\\%' in sanitised:
            return sanitised.replace('\\%', '\\\\%')
        return sanitised.replace('%', '\\\\%')

    def _sanitise_value(self, value):
        for character in ('"', "'"):
            if value.startswith(character):
                return self._sanitise_value(value[1:])
            if value.endswith(character):
                return self._sanitise_value(value[:-1])
        return value


class TestSTIX20Export(TestSTIX2Export):
    _attributes_v20 = defaultdict(lambda: defaultdict(dict))
    _objects_v20 = defaultdict(lambda: defaultdict(dict))
    _galaxies_v20 = defaultdict(lambda: defaultdict(dict))

    def _populate_attributes_documentation(self, attribute, **kwargs):
        attribute_type = attribute['type']
        self._attributes_v20[attribute_type]['MISP'] = dict(
            self._populate_attribute(attribute, exclude=_ATTRIBUTE_EXCLUSION_LIST)
        )
        stix_objects = kwargs['stix']
        if isinstance(stix_objects, list):
            self._attributes_v20[attribute_type]['STIX'] = [
                json.loads(obj.serialize()) for obj in stix_objects
            ]
            return
        self._attributes_v20[attribute_type]['STIX'] = json.loads(stix_objects.serialize())

    def _populate_galaxies_documentation(self, galaxy, name=None, summary=None, **kwargs):
        if name is None:
            name = galaxy['name']
        self._galaxies_v20[name]['MISP'] = json.loads(galaxy.to_json())
        if summary is not None:
            self._galaxies_v20['summary'][name] = summary
        self._galaxies_v20[name]['STIX'] = json.loads(kwargs['stix'].serialize())

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        self._objects_v20[name]['MISP'] = (
            [dict(self._populate_object(obj)) for obj in misp_object]
            if isinstance(misp_object, list) else
            dict(self._populate_object(misp_object))
        )
        if summary is not None:
            self._objects_v20['summary'][name] = summary
        stix_objects = kwargs['stix']
        if isinstance(stix_objects, list):
            self._objects_v20[name]['STIX'] = [
                json.loads(obj.serialize()) for obj in stix_objects
            ]
            return
        self._objects_v20[name]['STIX'] = json.loads(stix_objects.serialize())


class TestSTIX21Export(TestSTIX2Export):
    _attributes_v21 = defaultdict(lambda: defaultdict(dict))
    _objects_v21 = defaultdict(lambda: defaultdict(dict))
    _galaxies_v21 = defaultdict(lambda: defaultdict(dict))

    def _populate_attributes_documentation(self, attribute, **kwargs):
        feature = attribute['type']
        self._attributes_v21[feature]['MISP'] = dict(
            self._populate_attribute(attribute, exclude=_ATTRIBUTE_EXCLUSION_LIST)
        )
        stix_objects = kwargs['stix']
        if isinstance(stix_objects, list):
            self._attributes_v21[feature]['STIX'] = [
                json.loads(obj.serialize()) for obj in stix_objects
            ]
            return
        self._attributes_v21[feature]['STIX'] = json.loads(stix_objects.serialize())

    def _populate_galaxies_documentation(self, galaxy, name=None, summary=None, **kwargs):
        if name is None:
            name = galaxy['name']
        self._galaxies_v21[name]['MISP'] = json.loads(galaxy.to_json())
        if summary is not None:
            self._galaxies_v21['summary'][name] = summary
        self._galaxies_v21[name]['STIX'] = json.loads(kwargs['stix'].serialize())

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        self._objects_v21[name]['MISP'] = (
            [dict(self._populate_object(obj)) for obj in misp_object]
            if isinstance(misp_object, list) else
            dict(self._populate_object(misp_object))
        )
        if summary is not None:
            self._objects_v21['summary'][name] = summary
        stix_objects = kwargs['stix']
        if isinstance(stix_objects, list):
            self._objects_v21[name]['STIX'] = [
                json.loads(obj.serialize()) for obj in stix_objects
            ]
            return
        self._objects_v21[name]['STIX'] = json.loads(stix_objects.serialize())
