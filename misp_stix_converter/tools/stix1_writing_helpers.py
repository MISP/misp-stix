#!/usr/bin/env python3

import json
from .stix1_framing import SCHEMALOC_DICT, _handle_namespaces
from cybox.core.observable import Observables
from pathlib import Path
from stix.core import (
    Campaigns, CoursesOfAction, Indicators, STIXPackage, ThreatActors)
from stix.core.ttps import TTPs

_cybox_features = (
    'cybox_major_version', 'cybox_minor_version', 'cybox_update_version'
)


def write_campaigns(campaigns: Campaigns, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        campaigns = campaigns.to_xml(include_namespaces=True).decode()
        return _format_xml_objects(
            campaigns, header_length=21, footer_length=23
        )
    return ', '.join(campaign.to_json() for campaign in campaigns.campaign)


def write_campaigns_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Campaigns>\n'
    return ']'


def write_campaigns_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Campaigns>\n'
    return '"campaigns": ['


def write_courses_of_action(
        courses_of_action: CoursesOfAction, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        courses_of_action = courses_of_action.to_xml(
            include_namespaces=False).decode()
        return _format_xml_objects(
            courses_of_action, header_length=27, footer_length=29
        )
    return ', '.join(
        course_of_action.to_json() for course_of_action
        in courses_of_action.course_of_action
    )


def write_courses_of_action_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Courses_Of_Action>\n'
    return ']'


def write_courses_of_action_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Courses_Of_Action>\n'
    return '"courses_of_action": ['


def write_events(package: STIXPackage, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        if package.related_packages is not None:
            length = 135 + len(package.id_) + len(package.version)
            return package.to_xml(include_namespaces=False).decode()[length:-82]
        content = '\n            '.join(
            package.to_xml(include_namespaces=False).decode().split('\n')
        )
        return f'            {content}\n'
    if package.related_packages is not None:
        return ', '.join(
            related_package.to_json() for related_package
            in package.related_packages
        )
    return json.dumps({'package': package.to_dict()})


def write_indicators(indicators: Indicators, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        indicators = indicators.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(
            indicators, header_length=22, footer_length=24
        )
    return f"{', '.join(indctr.to_json() for indctr in indicators.indicator)}"


def write_indicators_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Indicators>\n'
    return ']'


def write_indicators_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Indicators>\n'
    return '"indicators": ['


def write_observables(
        observables: Observables, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        header_length = 20
        for field in _cybox_features:
            if getattr(observables, field, None) is not None:
                header_length += len(field) + len(getattr(observables, field)) + 4
        observables = observables.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(
            observables, header_length=header_length, footer_length=22
        )
    return f"{', '.join(obs.to_json() for obs in observables.observables)}"


def write_observables_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Observables>\n'
    return ']'


def write_observables_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        observables = Observables()
        versions = ' '.join(
            f'{feature}="{getattr(observables, feature)}"'
            for feature in _cybox_features
        )
        return f'    <stix:Observables {versions}>\n'
    return '"observables": ['


def write_threat_actors(
        threat_actors: ThreatActors, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        threat_actors = threat_actors.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(
            threat_actors, header_length=24, footer_length=26
        )
    return ', '.join(
        threat_actor.to_json() for threat_actor in threat_actors.threat_actor
    )


def write_threat_actors_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Threat_Actors>\n'
    return ']'


def write_threat_actors_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Threat_Actors>\n'
    return '"threat_actors": ['


def write_ttps(ttps: TTPs, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        ttps = ttps.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(ttps, header_length=16, footer_length=18)
    return ', '.join(ttp.to_json() for ttp in ttps.ttp)


def write_ttps_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:TTPs>\n'
    return ']}'


def write_ttps_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:TTPs>\n'
    return '"ttps": {"ttps": ['


def _format_xml_objects(
        objects: str, header_length=0, footer_length=0, to_replace='\n',
        replacement='\n    ') -> str:
    if footer_length == 0:
        return f'    {objects[header_length:].replace(to_replace, replacement)}\n'
    return f'    {objects[header_length:-footer_length].replace(to_replace, replacement)}\n'


def _write_raw_stix(
        package: STIXPackage, filename: Path | str, namespace: str,
        org: str, return_format: str) -> bool:
    if return_format == 'xml':
        namespaces = _handle_namespaces(namespace, org)
        with open(filename, 'wb') as f:
            f.write(
                package.to_xml(
                    auto_namespace=False,
                    ns_dict=namespaces,
                    schemaloc_dict=SCHEMALOC_DICT
                )
            )
    else:
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(package.to_dict(), indent=4))