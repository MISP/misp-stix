#!/usr/bin/env python3

from ..stix2misp.external_stix2_to_misp import ExternalSTIX2toMISPParser
from ..stix2misp.internal_stix2_to_misp import InternalSTIX2toMISPParser

_MISP_STIX_tags = ('misp:tool="MISP-STIX-Converter"', 'misp:tool="misp2stix2"')
_STIX2_event_types = ('grouping', 'report')


def get_stix2_parser(
        from_misp: bool, distribution: int, sharing_group_id: int | None,
        title: str | None, producer: str | None, force_contextual_data: bool,
        galaxies_as_tags: bool, single_event: bool, organisation_uuid: str,
        cluster_distribution: int, cluster_sharing_group_id: int | None) -> tuple:
    args = {
        'distribution': distribution,
        'force_contextual_data': force_contextual_data,
        'galaxies_as_tags': galaxies_as_tags,
        'producer': producer,
        'sharing_group_id': sharing_group_id,
        'single_event': single_event,
        'title': title
    }
    if from_misp:
        return InternalSTIX2toMISPParser, args
    args.update(
        {
            'cluster_distribution': cluster_distribution,
            'cluster_sharing_group_id': cluster_sharing_group_id,
            'organisation_uuid': organisation_uuid
        }
    )
    return ExternalSTIX2toMISPParser, args


def is_stix2_from_misp(stix_objects: list):
    for stix_object in stix_objects:
        labels = stix_object.get('labels', [])
        if stix_object['type'] not in _STIX2_event_types or not labels:
            continue
        if any(tag in labels for tag in _MISP_STIX_tags):
            return True
    return False