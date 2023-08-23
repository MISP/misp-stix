#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from datetime import datetime


class TestSTIX(unittest.TestCase):

    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)

    @staticmethod
    def _datetime_from_str(timestamp):
        regex = '%Y-%m-%dT%H:%M:%S'
        if '.' in timestamp:
            regex = f'{regex}.%f'
        if timestamp.endswith('Z') or '+' in timestamp:
            regex = f'{regex}%z'
        return datetime.strptime(timestamp, regex)


class TestSTIX20(TestSTIX):
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

    def _check_grouping_features(self, grouping, event, identity_id):
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event['uuid']}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event['info'])
        self.assertEqual(grouping.created, timestamp)
        self.assertEqual(grouping.modified, timestamp)
        return grouping.object_refs
