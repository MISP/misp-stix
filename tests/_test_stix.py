#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import unittest
from collections import defaultdict
from datetime import datetime


class TestSTIX2(unittest.TestCase):
    _attributes = defaultdict(lambda: defaultdict(dict))
    _objects = defaultdict(lambda: defaultdict(dict))

    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)

    @staticmethod
    def _datetime_to_str(datetime_value):
        return datetime.strftime(datetime_value, '%Y-%m-%dT%H:%M:%S')

    def _populate_documentation(self, attribute = None, misp_object = None, **kwargs):
        if attribute is not None:
            self._populate_attributes_documentation(attribute, **kwargs)
        elif misp_object is not None:
            self._populate_objects_documentation(misp_object, **kwargs)

    def _sanitize_documentation(self, documentation):
        if isinstance(documentation, list):
            return [self._sanitize_documentation(value) for value in documentation]
        sanitized = {}
        for key, value in documentation.items():
            if key == 'to_ids':
                continue
            sanitized[key] = self._sanitize_documentation(value) if isinstance(value, (dict, list)) else value
        return sanitized


class TestSTIX20(TestSTIX2):
    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'sha224': 'SHA-224',
        'sha256': 'SHA-256',
        'sha384': 'SHA-384',
        'sha512': 'SHA-512',
        'sha512/224': 'SHA-224',
        'sha512/256': 'SHA-256',
        'ssdeep': 'ssdeep'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.upper()

    def _populate_attributes_documentation(self, attribute, **kwargs):
        attribute_type = attribute['type']
        if 'MISP' not in self._attributes[attribute_type]:
            self._attributes[attribute_type]['MISP'] = self._sanitize_documentation(attribute)
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = object_type.replace('_', ' ').title()
            self._attributes[attribute_type]['STIX'][feature] = documented

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        if 'MISP' not in self._objects[name]:
            self._objects[name]['MISP'] = self._sanitize_documentation(misp_object)
        if summary is not None:
            self._objects['summary'][name] = summary
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
            self._objects[name]['STIX'][feature] = documented


class TestSTIX21(TestSTIX2):
    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'sha224': 'SHA224',
        'sha256': 'SHA-256',
        'sha384': 'SHA384',
        'sha512': 'SHA-512',
        'sha512/224': 'SHA-224',
        'sha512/256': 'SHA-256'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.upper()

    def _check_grouping_features(self, grouping, event, identity_id):
        timestamp = self._datetime_from_timestamp(event['timestamp'])
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event['uuid']}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event['info'])
        self.assertEqual(grouping.created, timestamp)
        self.assertEqual(grouping.modified, timestamp)
        return grouping.object_refs

    def _check_misp_event_features_from_grouping(self, event, grouping):
        self.assertEqual(event.uuid, grouping.id.split('--')[1])
        self.assertEqual(event.info, grouping.name)
        self._assert_multiple_equal(
            event.timestamp,
            self._timestamp_from_datetime(grouping.created),
            self._timestamp_from_datetime(grouping.modified)
        )
        return (*event.objects, *event.attributes)

    def _populate_attributes_documentation(self, attribute, **kwargs):
        feature = attribute['type']
        if 'MISP' not in self._attributes[feature]:
            self._attributes[feature]['MISP'] = self._sanitize_documentation(attribute)
        if 'observed_data' in kwargs:
            documented = [json.loads(observable.serialize()) for observable in kwargs['observed_data']]
            self._attributes[feature]['STIX']['Observed Data'] = documented
        else:
            for object_type, stix_object in kwargs.items():
                documented = json.loads(stix_object.serialize())
                self._attributes[feature]['STIX'][object_type.capitalize()] = documented

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        if 'MISP' not in self._objects[name]:
            self._objects[name]['MISP'] = self._sanitize_documentation(misp_object)
        if summary is not None:
            self._objects['summary'][name] = summary
        if 'observed_data' in kwargs:
            documented = [json.loads(observable.serialize()) for observable in kwargs['observed_data']]
            self._objects[name]['STIX']['Observed Data'] = documented
        else:
            for object_type, stix_object in kwargs.items():
                documented = json.loads(stix_object.serialize())
                feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
                self._objects[name]['STIX'][feature] = documented
