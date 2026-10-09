#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import unittest
from datetime import datetime
from uuid import UUID, uuid5
from .test_events import (
    get_event_with_account_objects,
    get_event_with_account_objects_with_attachment,
    get_event_with_android_app_object, get_event_with_annotation_object,
    get_event_with_artifact_payload_object, get_event_with_asn_object,
    get_event_with_attack_pattern_object,
    get_event_with_course_of_action_object, get_event_with_cpe_asset_object,
    get_event_with_credential_object, get_event_with_directory_object,
    get_event_with_domain_ip_object_custom,
    get_event_with_domain_ip_object_standard, get_event_with_employee_object,
    get_event_with_file_and_pe_objects, get_event_with_file_object,
    get_event_with_file_object_with_artifact,
    get_event_with_geolocation_object, get_event_with_hashlookup_object,
    get_event_with_http_request_object, get_event_with_identity_object,
    get_event_with_image_object, get_event_with_intrusion_set_object,
    get_event_with_ip_port_object, get_event_with_legal_entity_object,
    get_event_with_lnk_object, get_event_with_malware_analysis_object,
    get_event_with_malware_object, get_event_with_mutex_object,
    get_event_with_netflow_object, get_event_with_network_connection_object,
    get_event_with_network_socket_object, get_event_with_news_agency_object,
    get_event_with_organization_object,
    get_event_with_patterning_language_objects, get_event_with_pe_objects,
    get_event_with_person_object, get_event_with_process_object,
    get_event_with_registry_key_and_values_objects,
    get_event_with_registry_key_object,
    get_event_with_registry_key_value_object, get_event_with_script_objects,
    get_event_with_url_object, get_event_with_user_account_object,
    get_event_with_x509_object)

_REPEAT_NAMESPACE = UUID('0b4c5e64-6c8c-4f3e-9b1a-7f0d6c2e8a51')


def append_further_values(misp_object: dict, relation: str, values: tuple,
                          to_ids: bool) -> list:
    # Further values of a relation the MISP object holds: each a copy of its
    # first attribute, data included, with a value and a uuid of its own
    first = next(
        attribute for attribute in misp_object['Attribute']
        if attribute['object_relation'] == relation
    )
    further = [
        {
            **{key: first[key] for key in ('type', 'object_relation', 'data')
               if key in first},
            'value': value, 'to_ids': to_ids,
            'uuid': str(uuid5(_REPEAT_NAMESPACE, value))
        }
        for value in values
    ]
    misp_object['Attribute'].extend(further)
    return further


def _get_event_with_domain_ip_object_standard_and_hostname():
    event = get_event_with_domain_ip_object_standard()
    event['Event']['Object'][0]['Attribute'].append(
        {
            'type': 'hostname', 'object_relation': 'hostname',
            'value': 'circl.lu', 'uuid': 'c5f4a3f3-4f69-4c2b-9b3e-3a1d0d2b6e11'
        }
    )
    return event


# One relation per place the STIX 2 export reads a relation it writes one
# value of, with a further value of the attribute's type as pymisp loads it,
# or several: (event, object name, relation, further value or values)
_REPEATED_RELATIONS = (
    (get_event_with_account_objects, 'gitlab-user', 'username', 'j0hnd03'),
    (get_event_with_account_objects_with_attachment, 'github-user',
     'username', 'octodog'),
    (get_event_with_android_app_object, 'android-app', 'name', 'Messenger'),
    (get_event_with_artifact_payload_object, 'artifact', 'mime_type',
     'application/octet-stream'),
    (get_event_with_artifact_payload_object, 'artifact', 'payload_bin',
     'artifact2.bin'),
    (get_event_with_asn_object, 'asn', 'asn', '66643'),
    (get_event_with_asn_object, 'asn', 'description', 'Another AS name'),
    (get_event_with_attack_pattern_object, 'attack-pattern', 'name',
     'Buffer Overflow in Environment Variables'),
    (get_event_with_course_of_action_object, 'course-of-action', 'name',
     'Block traffic to PIVY C2 Server (10.10.10.11)'),
    (get_event_with_cpe_asset_object, 'cpe-asset', 'vendor',
     'Microsoft Corporation'),
    (get_event_with_credential_object, 'credential', 'username', 'admin'),
    (get_event_with_directory_object, 'directory', 'path',
     '/var/www/MISP/app/tmp'),
    (get_event_with_domain_ip_object_custom, 'domain-ip', 'hostname',
     'misp-project.org'),
    (_get_event_with_domain_ip_object_standard_and_hostname, 'domain-ip',
     'hostname', 'misp-project.org'),
    (get_event_with_employee_object, 'employee', 'first-name', 'Jane'),
    (get_event_with_file_object, 'file', 'md5',
     'b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_file_object, 'file', 'path', '/var/www/MISP/app/tmp'),
    (get_event_with_file_object, 'file', 'malware-sample',
     'oui2|b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_file_object, 'file', 'attachment', 'non2'),
    (get_event_with_file_object_with_artifact, 'file', 'attachment',
     'non2'),
    (get_event_with_file_and_pe_objects, 'pe', 'imphash',
     ('b2a5abfeef9e36964281a31e17b57c97',
      'c3a5abfeef9e36964281a31e17b57c97')),
    (get_event_with_file_and_pe_objects, 'pe-section', 'name', '.text'),
    (get_event_with_pe_objects, 'pe', 'imphash',
     'b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_pe_objects, 'pe-section', 'name', '.text'),
    (get_event_with_hashlookup_object, 'hashlookup', 'MD5',
     'b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_http_request_object, 'http-request', 'host',
     'misp-project.org'),
    (get_event_with_identity_object, 'identity', 'name', 'Jane Doe'),
    (get_event_with_image_object, 'image', 'filename', 'MISP.png'),
    (get_event_with_image_object, 'image', 'attachment', 'MISP.png'),
    (get_event_with_intrusion_set_object, 'intrusion-set', 'name',
     'Bobcat Breakout'),
    (get_event_with_ip_port_object, 'ip-port', 'first-seen',
     '2020-10-26T16:22:00Z'),
    (get_event_with_legal_entity_object, 'legal-entity', 'name',
     'Umbrella Holdings'),
    (get_event_with_lnk_object, 'lnk', 'md5',
     'b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_lnk_object, 'lnk', 'malware-sample',
     'oui2|b2a5abfeef9e36964281a31e17b57c97'),
    (get_event_with_malware_object, 'malware', 'name', 'Poison Ivy 2'),
    (get_event_with_mutex_object, 'mutex', 'name', 'MutexTest2'),
    (get_event_with_netflow_object, 'netflow', 'src-port', '8080'),
    (get_event_with_network_connection_object, 'network-connection',
     'ip-dst', '5.6.7.9'),
    (get_event_with_network_socket_object, 'network-socket', 'dst-port',
     '8443'),
    (get_event_with_news_agency_object, 'news-agency', 'name',
     'Agence France-Presse International'),
    (get_event_with_organization_object, 'organization', 'name', 'CIRCL'),
    (get_event_with_person_object, 'person', 'first-name', 'Jane'),
    (get_event_with_process_object, 'process', 'pid', '2511'),
    (get_event_with_process_object, 'process', 'parent-pid', '2108'),
    (get_event_with_process_object, 'process', 'image', 'other_process.exe'),
    (get_event_with_registry_key_object, 'registry-key', 'key',
     'hkey_local_machine\\system\\bar\\baz'),
    (get_event_with_registry_key_object, 'registry-key', 'last-modified',
     '2020-10-26T16:22:00Z'),
    (get_event_with_registry_key_and_values_objects, 'registry-key', 'key',
     'hkey_local_machine\\system\\bar\\baz'),
    (get_event_with_registry_key_and_values_objects, 'registry-key-value',
     'name', 'Bar'),
    (get_event_with_script_objects, 'script', 'filename', 'infected2.py'),
    (get_event_with_url_object, 'url', 'url', 'https://www.circl.lu/services'),
    (get_event_with_user_account_object, 'user-account', 'username',
     'adulau'),
    (get_event_with_x509_object, 'x509', 'issuer', 'Other Issuer Name')
)

# Stands in for any `definition.json` a traversing object name could reach:
# the values are recognisable so a leak into the converted data is obvious.
PLANTED_TEMPLATE = {
    'name': 'planted',
    'uuid': 'deadbeef-0000-4000-8000-000000000000',
    'meta-category': 'LEAKED-CATEGORY',
    'description': 'CONTENTS OF A FILE OUTSIDE THE TEMPLATE DIRECTORY',
    'version': 99,
    'attributes': {}
}


class TestSTIX(unittest.TestCase):

    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)

    def _check_output_write_safety(self, conversion, filename, **kwargs):
        # What a conversion writes is as sensitive as the document it came
        # from: the file is readable by its owner alone whatever the process
        # umask allows, and one that already exists is only replaced when the
        # caller asked for it, with the refusal naming the file it left as it
        # was
        import os
        umask = os.umask(0)
        try:
            results = conversion(filename, **kwargs)
        finally:
            os.umask(umask)
        self.assertEqual(results['success'], 1)
        output = results['results'][0]
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        written = output.read_text(encoding='utf-8')
        with self.assertRaises(FileExistsError) as context:
            conversion(filename, **kwargs)
        self.assertIn(str(output), str(context.exception))
        self.assertIn('overwrite', str(context.exception))
        self.assertEqual(output.read_text(encoding='utf-8'), written)
        results = conversion(filename, overwrite=True, **kwargs)
        self.assertEqual(results['success'], 1)
        self.assertEqual(results['results'][0], output)

    def _check_output_dir_handling(
            self, conversion, filename, outputs: int = 1, **kwargs):
        # `output_dir` is documented as a `Path` or a `str`, and how many MISP
        # events a document yields is the document's own shape rather than a
        # caller parameter: both types work whichever branch that shape
        # selects, and a location that does not exist yet is created rather
        # than failing at write time - `str` and creation crossed, since the
        # branch reached for one of them is where neither held
        #
        # `_check_output_dir_refuses_a_file` covers the other half, for the
        # conversions that can reach the per-event branch
        from pathlib import Path
        from tempfile import TemporaryDirectory
        for single_event in (True, False):
            for as_str in (False, True):
                for exists in (True, False):
                    with TemporaryDirectory() as tmp_dir:
                        directory = (
                            Path(tmp_dir) / 'missing' / 'output'
                        ).resolve()
                        if exists:
                            directory.mkdir(parents=True)
                        results = conversion(
                            filename, single_event=single_event,
                            output_dir=(
                                str(directory) if as_str else directory
                            ), **kwargs
                        )
                        self.assertEqual(results['success'], 1)
                        self.assertTrue(directory.is_dir())
                        self.assertEqual(
                            len(results['results']),
                            1 if single_event else outputs
                        )
                        self._check_written_in(directory, results['results'])

    def _check_output_dir_refuses_a_file(self, conversion, filename, taken):
        # A directory is the only thing that can hold one file per MISP event,
        # so unlike the output funnels an existing file is not read as the
        # output file: the conversion says which path it could not make a
        # directory of, and leaves the file as it was
        with open(taken, 'wt', encoding='utf-8') as f:
            f.write('taken')
        with self.assertRaises(FileExistsError) as context:
            conversion(filename, output_dir=taken)
        self.assertIn(str(taken), str(context.exception))
        self.assertEqual(taken.read_text(encoding='utf-8'), 'taken')

    def _check_written_in(self, directory, outputs):
        for output in outputs:
            self.assertEqual(output.parent, directory)
            self.assertTrue(output.is_file())

    @staticmethod
    def _plant_template_definition(directory):
        """Plant a template definition outside the MISP objects directory.

        :param directory: a directory outside the template tree
        :return: the object name that reaches it from the templates path
        """
        from os.path import relpath
        from pathlib import Path
        from pymisp import AbstractMISP
        planted = Path(directory) / 'planted'
        planted.mkdir()
        with open(planted / 'definition.json', 'wt', encoding='utf-8') as f:
            json.dump(PLANTED_TEMPLATE, f)
        return relpath(planted, AbstractMISP().misp_objects_path)

    @staticmethod
    def _datetime_from_str(timestamp):
        if isinstance(timestamp, datetime):
            return timestamp
        regex = f"%Y-%m-%d{'T' if 'T' in timestamp else ' '}%H:%M:%S"
        if '.' in timestamp:
            regex = f'{regex}.%f'
        if timestamp.endswith('Z') or '+' in timestamp:
            regex = f'{regex}%z'
        return datetime.strptime(timestamp, regex)


class TestSTIX20(TestSTIX):
    _REPEATED_RELATIONS = _REPEATED_RELATIONS

    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'SHA-1': 'sha1',
        'sha224': 'SHA-224',
        'SHA-224': 'sha224',
        'sha256': 'SHA-256',
        'SHA-256': 'sha256',
        'sha384': 'SHA-384',
        'SHA-384': 'sha384',
        'sha512': 'SHA-512',
        'SHA-512': 'sha512',
        'sha512/224': 'SHA-224',
        'sha512/256': 'SHA-256',
        'ssdeep': 'ssdeep'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.lower() if hash_type.isupper() else hash_type.upper()


class TestSTIX21(TestSTIX):
    _REPEATED_RELATIONS = (
        *_REPEATED_RELATIONS,
        (get_event_with_annotation_object, 'annotation', 'text',
         'Cloudflare public DNS'),
        (get_event_with_geolocation_object, 'geolocation', 'city', 'Columbia'),
        (get_event_with_malware_analysis_object, 'malware-analysis', 'result',
         'benign'),
        (get_event_with_registry_key_value_object, 'registry-key-value',
         'data', '%DATA%\\asdfghjkl'),
        (get_event_with_patterning_language_objects, 'owasp-crs-rule',
         'rule-id', '942101'),
        (get_event_with_patterning_language_objects, 'nova-rule', 'rule-name',
         'Other nova rule'),
        (get_event_with_patterning_language_objects, 'sigma',
         'sigma-rule-name', 'Other sigma rule'),
        (get_event_with_patterning_language_objects, 'suricata', 'version',
         '7.0'),
        (get_event_with_patterning_language_objects, 'wazuh-rule', 'rule-id',
         '100002'),
        (get_event_with_patterning_language_objects, 'yara',
         'yara-rule-name', 'Other yara rule')
    )

    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'SHA-1': 'sha1',
        'sha224': 'SHA224',
        'SHA224': 'sha224',
        'sha256': 'SHA-256',
        'SHA-256': 'sha256',
        'sha384': 'SHA384',
        'SHA384': 'sha384',
        'sha512': 'SHA-512',
        'SHA-512': 'sha512',
        'sha512/224': 'SHA224',
        'sha512/256': 'SHA-256'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.lower() if hash_type.isupper() else hash_type.upper()

    def _check_grouping_features(self, grouping, identity_id):
        event = self.parser._misp_event
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event.uuid}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event.info)
        self.assertEqual(grouping.created, event.timestamp)
        self.assertEqual(grouping.modified, event.timestamp)
        return grouping.object_refs
