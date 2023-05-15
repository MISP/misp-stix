# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import os
import re
import sys
from .misp2stix.framing import stix1_attributes_framing, stix1_framing
from .misp2stix.misp_to_stix1 import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser)
from .misp2stix.misp_to_stix20 import MISPtoSTIX20Parser
from .misp2stix.misp_to_stix21 import MISPtoSTIX21Parser
from .misp2stix.stix1_mapping import NS_DICT, SCHEMALOC_DICT
from .stix2misp.external_stix1_to_misp import ExternalSTIX1toMISPParser
from .stix2misp.external_stix2_to_misp import ExternalSTIX2toMISPParser
from .stix2misp.internal_stix1_to_misp import InternalSTIX1toMISPParser
from .stix2misp.internal_stix2_to_misp import InternalSTIX2toMISPParser
from collections import defaultdict
from cybox.core.observable import Observables
from mixbox import idgen
from mixbox.namespaces import (
    Namespace, NamespaceNotFoundError, register_namespace)
from pathlib import Path
from stix.core import (
    Campaigns, CoursesOfAction, Indicators, ThreatActors,
    STIXHeader, STIXPackage)
from stix.core.ttps import TTPs
from stix2.base import STIXJSONEncoder
from stix2.parsing import parse as stix2_parser
from stix2.v20 import Bundle as Bundle_v20
from stix2.v21 import Bundle as Bundle_v21
from typing import List, Optional, Union
from uuid import uuid4

_cybox_features = (
    'cybox_major_version', 'cybox_minor_version', 'cybox_update_version'
)
_default_namespace = 'https://misp-project.org'
_default_org = 'MISP'
_files_type = Union[Path, str]
_MISP_STIX_tags = ('misp:tool="MISP-STIX-Converter"', 'misp:tool="misp2stix2"')
_STIX1_default_format = 'xml'
_STIX1_default_version = '1.1.1'
_STIX1_features = (
    'campaigns', 'courses_of_action', 'exploit_targets', 'indicators',
    'observables', 'threat_actors', 'ttps'
)
_STIX1_valid_formats = ('json', 'xml')
_STIX1_valid_versions = ('1.1.1', '1.2')
_STIX2_event_types = ('grouping', 'report')


################################################################################
#                         MISP to STIX MAIN FUNCTIONS.                         #
################################################################################


class AttributeCollectionHandler():
    def __init__(self, return_format):
        self.__return_format = return_format
        self.__features = defaultdict(dict)

    @property
    def features(self):
        return self.__features

    @property
    def campaigns(self):
        return self.features['campaigns'].get('filename')

    @campaigns.setter
    def campaigns(self, filename):
        self.features['campaigns']['filename'] = f'{filename}.{self.return_format}'
        self.features['campaigns'].update(
            {
                'header': '    <stix:Campaigns>\n',
                'footer': '    </stix:Campaigns>\n'
            } if self.return_format == 'xml' else {
                'header': '"campaigns": [',
                'footer': '], '
            }
        )

    @property
    def campaigns_footer(self):
        return self.features['campaigns']['footer']

    @property
    def campaigns_header(self):
        return self.features['campaigns']['header']

    @property
    def courses_of_action(self):
        return self.features['courses_of_action'].get('filename')

    @courses_of_action.setter
    def courses_of_action(self, filename):
        self.features['courses_of_action']['filename'] = f'{filename}.{self.return_format}'
        self.features['courses_of_action'].update(
            {
                'header': '    <stix:CoursesOfAction>\n',
                'footer': '    </stix:CoursesOfAction>\n'
            } if self.return_format == 'xml' else {
                'header': '"courses_of_action": [',
                'footer': '], '
            }
        )

    @property
    def courses_of_action_footer(self):
        return self.features['courses_of_action']['footer']

    @property
    def courses_of_action_header(self):
        return self.features['courses_of_action']['header']

    @property
    def exploit_targets(self):
        return self.features['exploit_targets'].get('filename')

    @exploit_targets.setter
    def exploit_targets(self, filename):
        self.features['exploit_targets']['filename'] = f'{filename}.{self.return_format}'
        self.features['exploit_targets'].update(
            {
                'header': '    <stix:ExploitTargets>\n',
                'footer': '    </stix:ExploitTargets>\n'
            } if self.return_format == 'xml' else {
                'header': '"exploit_targets": {"exploit_targets": [',
                'footer': ']}, '
            }
        )

    @property
    def exploit_targets_footer(self):
        return self.features['exploit_targets']['footer']

    @property
    def exploit_targets_header(self):
        return self.features['exploit_targets']['header']

    @property
    def indicators(self):
        return self.features['indicators'].get('filename')

    @indicators.setter
    def indicators(self, filename):
        self.features['indicators']['filename'] = f'{filename}.{self.return_format}'
        self.features['indicators'].update(
            {
                'header': '    <stix:Indicators>\n',
                'footer': '    </stix:Indicators>\n'
            } if self.return_format == 'xml' else {
                'header': '"indicators": [',
                'footer': '], '
            }
        )

    @property
    def indicators_footer(self):
        return self.features['indicators']['footer']

    @property
    def indicators_header(self):
        return self.features['indicators']['header']

    @property
    def observables(self):
        return self.features['observables'].get('filename')

    @observables.setter
    def observables(self, filename):
        self.features['observables']['filename'] = f'{filename}.{self.return_format}'
        self.features['observables'].update(
            {
                'header': '    <stix:Observables>\n',
                'footer': '    </stix:Observables>\n'
            } if self.return_format == 'xml' else {
                'header': '"observables": {"observables": [',
                'footer': ']}, '
            }
        )

    @property
    def observables_footer(self):
        return self.features['observables']['footer']

    @property
    def observables_header(self):
        return self.features['observables']['header']

    @property
    def return_format(self) -> str:
        return self.__return_format

    @property
    def threat_actors(self):
        return self.features['threat_actors'].get('filename')

    @threat_actors.setter
    def threat_actors(self, filename):
        self.features['threat_actors']['filename'] = f'{filename}.{self.return_format}'
        self.features['threat_actors'].update(
            {
                'header': '    <stix:ThreatActors>\n',
                'footer': '    </stix:ThreatActors>\n'
            } if self.return_format == 'xml' else {
                'header': '"threat_actors": [',
                'footer': '], '
            }
        )

    @property
    def threat_actors_footer(self):
        return self.features['threat_actors']['footer']

    @property
    def threat_actors_header(self):
        return self.features['threat_actors']['header']

    @property
    def ttps(self):
        return self.features['ttps'].get('filename')

    @ttps.setter
    def ttps(self, filename):
        self.features['ttps']['filename'] = f'{filename}.{self.return_format}'
        self.features['ttps'].update(
            {
                'header': '    <stix:TTPs>\n',
                'footer': '    </stix:TTPs>\n'
            } if self.return_format == 'xml' else {
                'header': '"ttps": {"ttps": [',
                'footer': ']}, '
            }
        )

    @property
    def ttps_footer(self):
        return self.features['ttps']['footer']

    @property
    def ttps_header(self):
        return self.features['ttps']['header']


def misp_attribute_collection_to_stix1(
        output_filename: _files_type, *input_files: List[_files_type],
        return_format: str=_STIX1_default_format,
        version: str=_STIX1_default_version, in_memory: bool=False,
        namespace: str=_default_namespace, org: str=_default_org):
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    parser = MISPtoSTIX1AttributesParser(org, version)
    if len(input_files) == 1:
        parser.parse_json_content(input_files[0])
        return _write_raw_stix(
            parser.stix_package, output_filename, namespace, org, return_format
        )
    if in_memory:
        package = _create_stix_package(org, version)
        for filename in input_files:
            parser.parse_json_content(filename)
            current = parser.stix_package
            for campaign in current.campaigns:
                package.add_campaign(campaign)
            for course_of_action in current.courses_of_action:
                package.add_course_of_action(course_of_action)
            for exploit_target in current.exploit_targets:
                package.add_exploit_target(exploit_target)
            for indicator in current.indicators:
                package.add_indicator(indicator)
            for observable in current.observables:
                package.add_observable(observable)
            for threat_actor in current.threat_actors:
                package.add_threat_actor(threat_actor)
            if current.ttps is not None:
                for ttp in current.ttps:
                    package.add_ttp(ttp)
        return _write_raw_stix(
            package, output_filename, namespace, org, return_format
        )
    current_path = Path(output_filename).parent.resolve()
    handler = AttributeCollectionHandler(return_format)
    header, _, footer = stix1_attributes_framing(
        namespace, org, return_format, version
    )
    for input_file in input_files:
        parser.parse_json_content(input_file)
        current = parser.stix_package
        for feature in _STIX1_features:
            values = getattr(current, feature)
            if values is not None and values:
                content = globals()[f'_get_{feature}'](values, return_format)
                if not content:
                    continue
                filename = getattr(handler, feature)
                if filename is None:
                    setattr(handler, feature, uuid4())
                    filename = getattr(handler, feature)
                    with open(current_path / filename, 'wt', encoding='utf-8') as f:
                        current_header = getattr(handler, f'{feature}_header')
                        f.write(f'{current_header}{content}')
                    continue
                with open(current_path / filename, 'at', encoding='utf-8') as f:
                    f.write(content)
    with open(output_filename, 'wt', encoding='utf-8') as result:
        result.write(header)
        actual_features = handler.features
        for feature in actual_features:
            filename = getattr(handler, feature)
            if filename is not None:
                with open(current_path / filename, 'rt', encoding='utf-8') as current:
                    content = current.read() if return_format == 'xml' else current.read()[:-2]
                current_footer = getattr(handler, f'{feature}_footer')
                if return_format == 'json' and feature == actual_features[-1]:
                    current_footer = current_footer[:-2]
                result.write(f'{content}{current_footer}')
                os.remove(current_path / filename)
        result.write(footer)
    return 1


def misp_event_collection_to_stix1(
        output_filename: _files_type, *input_files: List[_files_type],
        return_format: str=_STIX1_default_format,
        version: str=_STIX1_default_version, in_memory: bool=False, 
        namespace: str=_default_namespace, org: str=_default_org):
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    parser = MISPtoSTIX1EventsParser(org, version)
    if in_memory or len(input_files) == 1:
        package = _create_stix_package(org, version)
        for filename in input_files:
            parser.parse_json_content(filename)
            if parser.stix_package.related_packages is not None:
                for related_package in parser.stix_package.related_packages:
                    package.add_related_package(related_package)
            else:
                package.add_related_package(parser.stix_package)
        return _write_raw_stix(
            package, output_filename, namespace, org, return_format
        )
    header, separator, footer = stix1_framing(
        namespace, org, return_format, version
    )
    parser.parse_json_content(input_files[0])
    content = _get_events(parser.stix_package, return_format)
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(f'{header}{content}')
    for filename in input_files[1:]:
        parser.parse_json_content(filename)
        content = _get_events(parser.stix_package, return_format)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{separator}{content}')
    with open(output_filename, 'at', encoding='utf-8') as f:
        f.write(footer)
    return 1


def misp_collection_to_stix2_0(
        output_filename: _files_type, *input_files: List[_files_type],
        in_memory: bool=False):
    parser = MISPtoSTIX20Parser()
    if in_memory or len(input_files) == 1:
        for filename in input_files:
            parser.parse_json_content(filename)
        objects = parser.stix_objects
        with open(output_filename, 'wt', encoding='utf-8') as f:
            f.write(
                json.dumps(Bundle_v20(objects), cls=STIXJSONEncoder, indent=4)
            )
        return 1
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(
            f'{json.dumps(Bundle_v20(), cls=STIXJSONEncoder, indent=4)[:-2]},'
            '\n    "objects": [\n'
        )
    for filename in input_files[:-1]:
        parser.parse_json_content(filename)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{json.dumps([parser.fetch_stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]},\n')
    parser.parse_json_content(input_files[-1])
    with open(output_filename, 'at', encoding='utf-8') as f:
        footer = '    ]\n}'
        f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]}\n{footer}')
    return 1


def misp_collection_to_stix2_1(
        output_filename: _files_type, *input_files: List[_files_type],
        in_memory: bool=False):
    parser = MISPtoSTIX21Parser()
    if in_memory or len(input_files) == 1:
        for filename in input_files:
            parser.parse_json_content(filename)
        objects = parser.stix_objects
        with open(output_filename, 'wt', encoding='utf-8') as f:
            f.write(
                json.dumps(Bundle_v21(objects), cls=STIXJSONEncoder, indent=4)
            )
        return 1
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(
            f'{json.dumps(Bundle_v21(), cls=STIXJSONEncoder, indent=4)[:-2]},'
            '\n    "objects": [\n'
        )
    for filename in input_files[:-1]:
        parser.parse_json_content(filename)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{json.dumps([parser.fetch_stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]},\n')
    parser.parse_json_content(input_files[-1])
    with open(output_filename, 'at', encoding='utf-8') as f:
        footer = '    ]\n}'
        f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]}\n{footer}')
    return 1


def misp_to_stix1(
        filename: _files_type, return_format: str, version: str,
        namespace=_default_namespace, org=_default_org,
        output_filename: Optional[_files_type]=None):
    if output_filename is None:
        output_filename = f'{filename}.out'
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    package = _create_stix_package(org, version)
    parser = MISPtoSTIX1EventsParser(org, version)
    parser.parse_json_content(filename)
    if parser.stix_package.related_packages is not None:
        for related_package in parser.stix_package.related_packages:
            package.add_related_package(related_package)
    else:
        package.add_related_package(parser.stix_package)
    return _write_raw_stix(
        package, output_filename, namespace, org, return_format
    )


def misp_to_stix2_0(
        filename: _files_type, output_filename: Optional[_files_type]=None):
    if output_filename is None:
        output_filename = f'{filename}.out'
    parser = MISPtoSTIX20Parser()
    parser.parse_json_content(filename)
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4))
    return 1


def misp_to_stix2_1(
        filename: _files_type, output_filename: Optional[_files_type]=None):
    if output_filename is None:
        output_filename = f'{filename}.out'
    parser = MISPtoSTIX21Parser()
    parser.parse_json_content(filename)
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4))
    return 1


################################################################################
#                         STIX to MISP MAIN FUNCTIONS.                         #
################################################################################

def stix_1_to_misp(
        filename: _files_type, output_filename: Optional[_files_type]=None):
    event = _load_stix_event(filename)
    if isinstance(event, str):
        return event
    title = event.stix_header.title
    from_misp = (title is not None and all(feature in title for feature in ('Export from ', 'MISP')))
    stix_parser = InternalSTIX1toMISPParser() if from_misp else ExternalSTIX1toMISPParser()
    stix_parser.load_event()
    stix_parser.build_misp_event(event)
    if output_filename is None:
        output_filename = f'{filename}.out'
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(stix_parser.misp_event.to_json(indent=4))
    return 1


def stix_2_to_misp(
        filename: _files_type, output_filename: Optional[_files_type]=None):
    with open(filename, 'rt', encoding='utf-8') as f:
        bundle = stix2_parser(
            f.read(), allow_custom=True, interoperability=True
        )
    stix_parser = InternalSTIX2toMISPParser() if _from_misp(bundle.objects) else ExternalSTIX2toMISPParser()
    stix_parser.load_stix_bundle(bundle)
    stix_parser.parse_stix_bundle()
    if output_filename is None:
        output_filename = f'{filename}.out'
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(stix_parser.misp_event.to_json(indent=4))
    return 1


################################################################################
#                        STIX PACKAGE CREATION HELPERS.                        #
################################################################################

def _create_stix_package(orgname: str, version: str) -> STIXPackage:
    package = STIXPackage()
    package.version = version
    header = STIXHeader()
    header.title = f"Export from {orgname}'s MISP"
    header.package_intents = "Threat Report"
    package.stix_header = header
    package.id_ = f"{orgname}:Package-{uuid4()}"
    return package


################################################################################
#                        STIX CONTENT LOADING FUNCTIONS                        #
################################################################################

def _from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object['type'] in _STIX2_event_types and any(tag in stix_object.get('labels', []) for tag in _MISP_STIX_tags):
            return True
    return False


def _load_stix_event(filename, tries=0):
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError:
        if tries == 1:
            return 4
        _update_namespaces()
        return _load_stix_event(filename, 1)
    except NotImplementedError:
        print('ERROR - Missing python library: stix_edh', file=sys.stderr)
        return 5
    except Exception:
        try:
            import maec
            return 2
        except ImportError:
            print('ERROR - Missing python library: maec', file=sys.stderr)
            return 3
    return 0


def _update_namespaces():
    # LIST OF ADDITIONAL NAMESPACES
    # can add additional ones whenever it is needed
    ADDITIONAL_NAMESPACES = [
        Namespace(
            'http://us-cert.gov/ciscp', 'CISCP',
            'http://www.us-cert.gov/sites/default/files/STIX_Namespace/'
            'ciscp_vocab_v1.1.1.xsd'
        ),
        Namespace(
            'http://taxii.mitre.org/messages/taxii_xml_binding-1.1', 'TAXII',
            'http://docs.oasis-open.org/cti/taxii/v1.1.1/cs01/schemas/'
            'TAXII-XMLMessageBinding-Schema.xsd'
        )
    ]
    for namespace in ADDITIONAL_NAMESPACES:
        register_namespace(namespace)


################################################################################
#                        STIX CONTENT WRITING FUNCTIONS                        #
################################################################################

def _format_xml_objects(
        objects: str, header_length=0, footer_length=0, to_replace='\n',
        replacement='\n    ') -> str:
    if footer_length == 0:
        return f'    {objects[header_length:].replace(to_replace, replacement)}\n'
    return f'    {objects[header_length:-footer_length].replace(to_replace, replacement)}\n'


def _get_campaigns(campaigns: Campaigns, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        campaigns = campaigns.to_xml(include_namespaces=True).decode()
        return _format_xml_objects(
            campaigns, header_length=21, footer_length=23
        )
    return ', '.join(campaign.to_json() for campaign in campaigns.campaign)


def _get_campaigns_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Campaigns>\n'
    return ']'


def _get_campaigns_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Campaigns>\n'
    return '"campaigns": ['


def _get_courses_of_action(
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


def _get_courses_of_action_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Courses_Of_Action>\n'
    return ']'


def _get_courses_of_action_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Courses_Of_Action>\n'
    return '"courses_of_action": ['


def _get_events(package: STIXPackage, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        if package.related_packages is not None:
            length = 96 + len(package.id_) + len(package.version)
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


def _get_indicators(indicators: Indicators, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        indicators = indicators.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(
            indicators, header_length=22, footer_length=24
        )
    return f"{', '.join(indctr.to_json() for indctr in indicators.indicator)}"


def _get_indicators_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Indicators>\n'
    return ']'


def _get_indicators_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Indicators>\n'
    return '"indicators": ['


def _get_observables(
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


def _get_observables_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Observables>\n'
    return ']'


def _get_observables_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        observables = Observables()
        versions = ' '.join(
            f'{feature}="{getattr(observables, feature)}"'
            for feature in _cybox_features
        )
        return f'    <stix:Observables {versions}>\n'
    return '"observables": ['


def _get_threat_actors(
        threat_actors: ThreatActors, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        threat_actors = threat_actors.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(
            threat_actors, header_length=24, footer_length=26
        )
    return ', '.join(
        threat_actor.to_json() for threat_actor in threat_actors.threat_actor
    )


def _get_threat_actors_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:Threat_Actors>\n'
    return ']'


def _get_threat_actors_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:Threat_Actors>\n'
    return '"threat_actors": ['


def _get_ttps(ttps: TTPs, return_format: str = 'xml') -> str:
    if return_format == 'xml':
        ttps = ttps.to_xml(include_namespaces=False).decode()
        return _format_xml_objects(ttps, header_length=16, footer_length=18)
    return ', '.join(ttp.to_json() for ttp in ttps.ttp)


def _get_ttps_footer(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    </stix:TTPs>\n'
    return ']}'


def _get_ttps_header(return_format: str = 'xml') -> str:
    if return_format == 'xml':
        return '    <stix:TTPs>\n'
    return '"ttps": {"ttps": ['


def _write_header(
        package: STIXPackage, filename: str, namespace: str, org: str,
        return_format: str) -> str:
    namespaces = namespaces = {namespace: org}
    namespaces.update(NS_DICT)
    try:
        idgen.set_id_namespace(Namespace(namespace, org))
    except TypeError:
        idgen.set_id_namespace(Namespace(namespace, org, "MISP"))
    if return_format == 'xml':
        xml_package = package.to_xml(
            auto_namespace=False, ns_dict=namespaces,
            schemaloc_dict=SCHEMALOC_DICT
        ).decode()
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(xml_package[:-21])
        return xml_package[-21:]
    json_package = package.to_json()
    with open(filename, 'wt', encoding='utf-8') as f:
        f.write(
            f'{json_package[:-1]}, "related_packages"'
            f': {json.dumps({"related_packages": []})[:-2]}'
        )
    return ']}}'


def _write_raw_stix(
        package: STIXPackage, filename: _files_type, namespace: str,
        org: str, return_format: str) -> bool:
    if return_format == 'xml':
        namespaces = namespaces = {namespace: org}
        namespaces.update(NS_DICT)
        try:
            idgen.set_id_namespace(Namespace(namespace, org))
        except TypeError:
            idgen.set_id_namespace(Namespace(namespace, org, "MISP"))
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
    return 1


################################################################################
#                            COMMAND LINE FUNCTIONS                            #
################################################################################

def _handle_output_dir(stix_args, filename):
    if stix_args.output_dir is None:
        return f'{filename}.out'
    return stix_args.output_dir / f'{filename.name}.out'


def _handle_output_filename(stix_args):
    if stix_args.output_name is None:
        return f'{stix_args.file[0]}.out'
    return stix_args.output_name


def _misp_to_stix(stix_args):
    if stix_args.version in ('1.1.1', '1.2'):
        if stix_args.feature == 'attribute':
            if len(stix_args.file) == 1:
                output_filename = _handle_output_filename(stix_args)
                status = misp_attribute_collection_to_stix1(
                    output_filename,
                    stix_args.file[0],
                    return_format = stix_args.format,
                    version = stix_args.version,
                    in_memory = not stix_args.tmp_files,
                    namespace = stix_args.namespace,
                    org = stix_args.org
                )
                if status != 1:
                    sys.exit(
                        f'Error while processing {stix_args.file[0]}'
                        f' - status code = {status}'
                    )
                return output_filename
            if stix_args.single_output:
                output = stix_args.output_dir / f'{uuid4()}.stix1.{stix_args.format}'
                status = misp_attribute_collection_to_stix1(
                    output,
                    *stix_args.file,
                    return_format = stix_args.format,
                    version = stix_args.version,
                    in_memory = not stix_args.tmp_files,
                    namespace = stix_args.namespace,
                    org = stix_args.org
                )
                if status != 1:
                    sys.exit(f'Error while processing your files - status code = {status}')
                return output
            results = []
            for filename in stix_args.file:
                output = _handle_output_dir(stix_args, filename)
                status = misp_attribute_collection_to_stix1(
                    output,
                    filename,
                    return_format = stix_args.format,
                    version = stix_args.version,
                    in_memory = not stix_args.tmp_files,
                    namespace = stix_args.namespace,
                    org = stix_args.org
                )
                if status == 1:
                    results.append(output)
                else:
                    print(f'Error while processing {filename} - status code = {status}', file=sys.stderr)
            return results
        if len(stix_args.file) == 1:
            output_filename = _handle_output_filename(stix_args)
            filename = stix_args.file[0]
            status = misp_to_stix1(
                filename,
                stix_args.format,
                stix_args.version,
                namespace=stix_args.namespace,
                org=stix_args.org,
                output_filename=output_filename
            )
            if status != 1:
                sys.exit(f'Error while processing {filename} - status code = {status}')
            return output_filename
        if stix_args.single_output:
            output = stix_args.output_dir / f'{uuid4()}.stix1.{stix_args.format}'
            status = misp_event_collection_to_stix1(
                output,
                *stix_args.file,
                return_format=stix_args.format,
                version=stix_args.version,
                in_memory=not stix_args.tmp_files,
                namespace=stix_args.namespace,
                org=stix_args.org
            )
            if status != 1:
                sys.exit(f'Error while processing your files - status code = {status}')
            return output
        results = []
        for filename in stix_args.file:
            output = _handle_output_dir(stix_args, filename)
            status = misp_to_stix1(
                filename,
                stix_args.format,
                stix_args.version,
                namespace=stix_args.namespace,
                version=stix_args.version,
                output_filename=output
            )
            if status == 1:
                results.append(output)
            else:
                print(f'Error while processing {filename} - status code = {status}', file=sys.stderr)
        return results, 1
    if len(stix_args.file) == 1:
        filename = stix_args.file[0]
        output_filename = _handle_output_filename(stix_args)
        args = (filename, output_filename)
        status = misp_to_stix2_0(*args) if stix_args.version == '2.0' else misp_to_stix2_1(*args)
        if status != 1:
            sys.exit(f'Error while processing {filename} - status code = {status}')
        return output_filename
    if stix_args.single_output:
        output = stix_args.output_dir / f"{uuid4()}.stix{stix_args.version.replace('.', '')}.json"
        method = misp_collection_to_stix2_0 if stix_args.version == '2.0' else misp_collection_to_stix2_1
        status = method(
            output,
            *stix_args.file,
            in_memory = not stix_args.tmp_files
        )
        if status != 1:
            sys.exit(f'Error while processing your files - status code = {status}')
        return output
    method = misp_to_stix2_0 if stix_args.version == '2.0' else misp_to_stix2_1
    return _process_files(stix_args, method)


def _process_files(stix_args, method):
    results = []
    for filename in stix_args.file:
        output_filename = _handle_output_dir(stix_args, filename)
        status = method(filename, output_filename=output_filename)
        if status == 1:
            results.append(output_filename)
        else:
            print(
                f'Error while processing {filename} - status code = {status}',
                file=sys.stderr
            )
    return results


def _stix_to_misp(stix_args):
    method = stix_2_to_misp if stix_args.version in ('2.0', '2.1') else stix_1_to_misp
    if len(stix_args.file) == 1:
        output_filename = _handle_output_filename(stix_args)
        method(stix_args.file[0], output_filename=output_filename)
        return output_filename
    return _process_files(stix_args, method)