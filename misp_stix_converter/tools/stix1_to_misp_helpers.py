#!/usr/bin/env python3

from ..stix2misp.external_stix1_to_misp import ExternalSTIX1toMISPParser
from ..stix2misp.internal_stix1_to_misp import InternalSTIX1toMISPParser
from stix.core import STIXPackage

def get_stix1_parser(
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
        return InternalSTIX1toMISPParser, args
    args.update(
        {
            'cluster_distribution': cluster_distribution,
            'cluster_sharing_group_id': cluster_sharing_group_id,
            'organisation_uuid': organisation_uuid
        }
    )
    return ExternalSTIX1toMISPParser, args


def is_stix1_from_misp(stix_package: STIXPackage) -> bool:
    try:
        title = stix_package.stix_header.title
    except AttributeError:
        return False
    return 'Export from ' in title and 'MISP' in title
