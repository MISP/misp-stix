#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
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