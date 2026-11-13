#!/usr/bin/env python3

import logging
from ..stix2misp.external_stix1_to_misp import ExternalSTIX1toMISPParser
from ..stix2misp.internal_stix1_to_misp import InternalSTIX1toMISPParser
from stix.core import STIXPackage
from typing import Optional

_logger = logging.getLogger(__name__)

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
    """Whether a STIX 1 package is a MISP export, from its header titles.

    The event export titles the package it writes; the collection export
    titles the packages it relates and leaves the wrapper around them
    untitled. A wrapper carrying no MISP title of its own is therefore
    classified from the related packages, and only when every one of them is
    titled as a MISP export: a MISP package related among another producer's
    is that producer's document.

    :param stix_package: the loaded package
    :return: whether the package is classified as a MISP export
    """
    from_misp = _is_misp_export_title(_header_title(stix_package)) or (
        _related_packages_are_misp_exports(stix_package)
    )
    if from_misp:
        _logger.warning(
            'MISP export title found in the STIX header - a classification '
            'signal that any producer can write.'
        )
    return from_misp


def _header_title(stix_package: STIXPackage) -> Optional[str]:
    return getattr(getattr(stix_package, 'stix_header', None), 'title', None)


def _is_misp_export_title(title: Optional[str]) -> bool:
    return bool(title) and 'Export from ' in title and 'MISP' in title


def _related_packages_are_misp_exports(stix_package: STIXPackage) -> bool:
    related_packages = stix_package.related_packages
    return bool(related_packages) and all(
        _is_misp_export_title(_header_title(related.item))
        for related in related_packages.related_package
    )
