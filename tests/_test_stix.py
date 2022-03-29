#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest


class TestSTIX2(unittest.TestCase):
    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)


class TestSTIX21(TestSTIX2):
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