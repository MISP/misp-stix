# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import os
import sys
from .misp2stix.framing import (
    _stix1_attributes_framing, _stix1_framing, _handle_namespaces,
    _create_stix_package)
from .misp2stix.misp_to_stix1 import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser)
from .misp2stix.misp_to_stix20 import MISPtoSTIX20Parser
from .misp2stix.misp_to_stix21 import MISPtoSTIX21Parser
from .misp2stix.stix1_mapping import NS_DICT, SCHEMALOC_DICT
from .stix2misp.external_stix1_to_misp import ExternalSTIX1toMISPParser
from .stix2misp.external_stix2_to_misp import (
    ExternalSTIX2toMISPParser, MISP_org_uuid)
from .stix2misp.importparser import _load_stix2_content
from .stix2misp.internal_stix1_to_misp import InternalSTIX1toMISPParser
from .stix2misp.internal_stix2_to_misp import InternalSTIX2toMISPParser
from collections import defaultdict
from cybox.core.observable import Observables
from mixbox import idgen
from mixbox.namespaces import (
    Namespace, NamespaceNotFoundError, register_namespace)
from pathlib import Path
from stix.core import (
    Campaigns, CoursesOfAction, Indicators, ThreatActors, STIXPackage)
from stix.core.ttps import TTPs
from stix2.base import STIXJSONEncoder
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
_STIX2_default_version = '2.1'
_STIX2_event_types = ('grouping', 'report')
_STIX2_valid_versions = ('2.0', '2.1')


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
        *input_files: List[_files_type], debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: Optional[str] = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    parser = MISPtoSTIX1AttributesParser(org, version)
    if len(input_files) == 1:
        try:
            filename = input_files[0]
            if isinstance(filename, str):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_filename(
                filename.parent, f'{filename.name}.out', output_dir, output_name
            )
            _write_raw_stix(
                parser.stix_package, name, namespace, org, return_format
            )
            return _generate_traceback(debug, parser, name)
        except Exception as exception:
            return {'fails': [f'{filename} -  {exception.__str__()}']}
    traceback = defaultdict(list)
    if single_output:
        stix_package = _create_stix_package(org, version)
        name = _check_filename(
            Path(__file__).resolve().parent / 'tmp',
            f'{stix_package.id_}.stix1.{return_format}',
            output_dir, output_name
        )
        if in_memory:
            for filename in input_files:
                try:
                    parser.parse_json_content(filename)
                    current = parser.stix_package
                    for campaign in current.campaigns:
                        stix_package.add_campaign(campaign)
                    for course_of_action in current.courses_of_action:
                        stix_package.add_course_of_action(course_of_action)
                    for exploit_target in current.exploit_targets:
                        stix_package.add_exploit_target(exploit_target)
                    for indicator in current.indicators:
                        stix_package.add_indicator(indicator)
                    for observable in current.observables:
                        stix_package.add_observable(observable)
                    for threat_actor in current.threat_actors:
                        stix_package.add_threat_actor(threat_actor)
                    if current.ttps is not None:
                        for ttp in current.ttps:
                            stix_package.add_ttp(ttp)
                except Exception as exception:
                    traceback['fails'].append(f'{filename} - {exception.__str__()}')
            if any(filename not in traceback.get('fails', []) for filename in input_files):
                _write_raw_stix(
                    stix_package, name, namespace, org, return_format
                )
                traceback.update(_generate_traceback(debug, parser, name))
            return traceback
        handler = AttributeCollectionHandler(return_format)
        tmp_path = name.parent
        for filename in input_files:
            try:
                parser.parse_json_content(filename)
                package = parser.stix_package
                for feature in _STIX1_features:
                    values = getattr(package, feature)
                    if values:
                        content = globals()[f'_get_{feature}'](values, return_format)
                        if not content:
                            continue
                        filename = getattr(handler, feature)
                        if filename is None:
                            setattr(handler, feature, uuid4())
                            filename = getattr(handler, feature)
                            with open(tmp_path / filename, 'wt', encoding='utf-8') as f:
                                current_header = getattr(handler, f'{feature}_header')
                                f.write(f'{current_header}{content}')
                            continue
                        with open(tmp_path / filename, 'at', encoding='utf-8') as f:
                            f.write(content)
            except Exception as exception:
                traceback['fails'].append(f'{filename} - {exception.__str__()}')
        if any(filename not in traceback.get('fails', []) for filename in input_files):
            header, _, footer = _stix1_attributes_framing(
                namespace, org, return_format, stix_package
            )
            with open(name, 'wt', encoding='utf-8') as result:
                result.write(header)
                actual_features = handler.features
                for feature in actual_features:
                    filename = getattr(handler, feature)
                    if filename is not None:
                        with open(tmp_path / filename, 'rt', encoding='utf-8') as current:
                            content = current.read() if return_format == 'xml' else current.read()[:-2]
                        current_footer = getattr(handler, f'{feature}_footer')
                        if return_format == 'json' and feature == actual_features[-1]:
                            current_footer = current_footer[:-2]
                        result.write(f'{content}{current_footer}')
                        os.remove(tmp_path / filename)
                result.write(footer)
            traceback.update(_generate_traceback(debug, parser, name))
        return traceback
    output_names = []
    for filename in input_files:
        try:
            if isinstance(filename, str):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_output(
                filename.parent, f'{filename.name}.out', output_dir
            )
            _write_raw_stix(
                parser.stix_package, name, namespace, org, return_format
            )
            output_names.append(name)
        except Exception as exception:
            traceback['fails'].append(f'{filename} - {exception.__str__()}')
    if output_names:
        traceback.update(_generate_traceback(debug, parser, *output_names))
    return traceback


def misp_event_collection_to_stix1(
        *input_files: List[_files_type], debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: Optional[str] = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    _write_args = (namespace, org, return_format)
    parser = MISPtoSTIX1EventsParser(org, version)
    if len(input_files) == 1:
        filename = input_files[0]
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_filename(
                filename.parent, f'{filename.name}.out', output_dir, output_name
            )
            _write_raw_stix(parser.stix_package, name, *_write_args)
            return _generate_traceback(debug, parser, name)
        except Exception as exception:
            return {'fails': [f'{filename} - {exception.__str__()}']}
    traceback = defaultdict(list)
    if single_output:
        stix_package = _create_stix_package(org, version, header=False)
        name = _check_filename(
            Path(__file__).resolve().parent / 'tmp',
            f'{stix_package.id_}.stix1.{return_format}',
            output_dir, output_name
        )
        if in_memory:
            for filename in input_files:
                try:
                    if not isinstance(filename, Path):
                        filename = Path(filename).resolve()
                    parser.parse_json_content(filename)
                    if parser.stix_package.related_packages is not None:
                        for related_package in parser.stix_package.related_packages:
                            stix_package.add_related_package(related_package)
                    else:
                        stix_package.add_related_package(parser.stix_package)
                except Exception as exception:
                    traceback['fails'].append(f'{filename} - {exception.__str__()}')
            if any(filename not in traceback.get('fails', []) for filename in input_files):
                _write_raw_stix(stix_package, name, *_write_args)
                traceback.update(_generate_traceback(debug, parser, name))
            return traceback
        header, separator, footer = _stix1_framing(
            namespace, org, return_format, stix_package
        )
        filename = input_files[0]
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            content = _get_events(parser.stix_package, return_format)
            with open(name, 'wt', encoding='utf-8') as f:
                f.write(f'{header}{content}')
        except Exception as exception:
            traceback['fails'].append(filename)
        for filename in input_files[1:]:
            try:
                if not isinstance(filename, Path):
                    filename = Path(filename).resolve()
                parser.parse_json_content(filename)
                content = _get_events(parser.stix_package, return_format)
                with open(name, 'at', encoding='utf-8') as f:
                    f.write(f'{separator}{content}')
            except Exception as exception:
                traceback['fails'].append(f'{filename} - {exception.__str__()}')
        with open(name, 'at', encoding='utf-8') as f:
            f.write(footer)
        traceback.update(_generate_traceback(debug, parser, name))
        return traceback
    output_names = []
    for filename in input_files:
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_output(
                filename.parent, f'{filename.name}.out', output_dir
            )
            _write_raw_stix(parser.stix_package, name, *_write_args)
            output_names.append(name)
        except Exception as exception:
            traceback['fails'].append(f'{filename} - {exception.__str__()}')
    if output_names:
        traceback.update(_generate_traceback(debug, parser, *output_names))
    return traceback


def misp_collection_to_stix2(
        *input_files: List[_files_type], debug: Optional[bool] = False,
        version: Optional[str] = _STIX2_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None) -> dict:
    if version not in _STIX2_valid_versions:
        version = _STIX2_default_version
    parser = MISPtoSTIX21Parser() if version == '2.1' else MISPtoSTIX20Parser()
    if len(input_files) == 1:
        filename = input_files[0]
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_filename(
                filename.parent, f'{filename.name}.out', output_dir, output_name
            )
            with open(name, 'wt', encoding='utf-8') as f:
                f.write(parser.bundle.serialize(indent=4))
            return _generate_traceback(debug, parser, name)
        except Exception as exception:
            return {'fails': [f'{filename} - {exception.__str__()}']}
    traceback = defaultdict(list)
    if single_output:
        if in_memory:
            for filename in input_files:
                try:
                    if not isinstance(filename, Path):
                        filename = Path(filename).resolve()
                    parser.parse_json_content(filename)
                except Exception as exception:
                    traceback['fails'].append(f'{filename} - {exception.__str__()}')
            if any(filename not in traceback.get('fails', []) for filename in input_files):
                bundle = parser.bundle
                name = _check_filename(
                    Path(__file__).resolve().parents[1] / 'tmp',
                    f"{bundle.id.split('--')[1]}.stix"
                    f"{version.replace('.', '')}.json",
                    output_dir, output_name
                )
                with open(name, 'wt', encoding='utf-8') as f:
                    f.write(bundle.serialize(indent=4))
                traceback.update(_generate_traceback(debug, parser, name))
            return traceback
        bundle = Bundle_v21() if version == '2.1' else Bundle_v20()
        name = _check_filename(
            Path(__file__).resolve().parents[1] / 'tmp',
            f"{bundle.id.split('--')[1]}.stix{version.replace('.', '')}.json",
            output_dir, output_name
        )
        with open(name, 'wt', encoding='utf-8') as f:
            f.write(f'{bundle.serialize(indent=4)[:-2]},\n    "objects": [\n')
        written = False
        try:
            filename = input_files[0]
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            stix_objects = json.dumps(
                [parser.fetch_stix_objects], cls=STIXJSONEncoder, indent=4
            )
            with open(name, 'at', encoding='utf-8') as f:
                f.write(stix_objects[8:-8])
            written = True
        except Exception as exception:
            traceback['fails'].append(f'{filename} - {exception.__str__()}')
        for filename in input_files[1:]:
            try:
                if not isinstance(filename, Path):
                    filename = Path(filename).resolve()
                parser.parse_json_content(filename)
                stix_objects = json.dumps(
                    [parser.fetch_stix_objects], cls=STIXJSONEncoder, indent=4
                )
                separator = ',\n' if written else ''
                with open(name, 'at', encoding='utf-8') as f:
                    f.write(f"{separator}{stix_objects[8:-8]}")
                written = True
            except Exception as exception:
                traceback['fails'].append(f'{filename} - {exception.__str__()}')
        if written:
            with open(name, 'at', encoding='utf-8') as f:
                f.write('\n    ]\n}')
            traceback.update(_generate_traceback(debug, parser, name))
        else:
            name.remove()
        return traceback
    output_names = []
    for filename in input_files:
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_content(filename)
            name = _check_output(
                filename.parent, f'{filename.name}.out', output_dir
            )
            with open(name, 'wt', encoding='utf-8') as f:
                f.write(parser.bundle.serialize(indent=4))
            output_names.append(name)
        except Exception as exception:
            traceback['fails'].append(f'{filename} - {exception.__str__()}')
    if output_names:
        traceback.update(_generate_traceback(debug, parser, *output_names))
    return traceback


def misp_to_stix1(
        filename: _files_type, debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: Optional[str] = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    parser = MISPtoSTIX1EventsParser(org, version)
    try:
        if not isinstance(filename, Path):
            filename = Path(filename).resolve()
        parser.parse_json_content(filename)
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        _write_raw_stix(
            parser.stix_package, name, namespace, org, return_format
        )
        return _generate_traceback(debug, parser, name)
    except Exception as exception:
        return {'fails': [f'{filename} - {exception.__str__()}']}


def misp_to_stix2(filename: _files_type, debug: Optional[bool] = False,
                  version: Optional[str] = _STIX2_default_version,
                  output_dir: Optional[_files_type] = None,
                  output_name: Optional[_files_type] = None) -> dict:
    if version not in _STIX2_valid_versions:
        version = _STIX2_default_version
    parser = MISPtoSTIX21Parser() if version == '2.1' else MISPtoSTIX20Parser()
    try:
        if not isinstance(filename, Path):
            filename = Path(filename).resolve()
        parser.parse_json_content(filename)
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        with open(name, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4))
        return _generate_traceback(debug, parser, name)
    except Exception as exception:
        return {'fails': [f'{filename} - {exception.__str__()}']}


################################################################################
#                         STIX to MISP MAIN FUNCTIONS.                         #
################################################################################

def stix_1_to_misp(
        filename: _files_type, output_filename: Optional[_files_type]=None):
    event = _load_stix_event(filename)
    if isinstance(event, str):
        return event
    title = event.stix_header.title
    from_misp = (
        title is not None and
        all(feature in title for feature in ('Export from ', 'MISP'))
    )
    stix_parser = (
        InternalSTIX1toMISPParser() if from_misp
        else ExternalSTIX1toMISPParser()
    )
    stix_parser.load_event()
    stix_parser.build_misp_event(event)
    if output_filename is None:
        output_filename = f'{filename}.out'
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(stix_parser.misp_event.to_json(indent=4))
    return 1


def stix_2_to_misp(filename: _files_type,
                   cluster_distribution: Optional[int] = 0,
                   cluster_sharing_group_id: Optional[int] = None,
                   debug: Optional[bool] = False,
                   distribution: Optional[int] = 0,
                   galaxies_as_tags: Optional[bool] = False,
                   organisation_uuid: Optional[str] = MISP_org_uuid,
                   output_dir: Optional[_files_type]=None,
                   output_name: Optional[_files_type]=None,
                   sharing_group_id: Optional[int] = None,
                   single_event: Optional[bool] = False) -> dict:
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    try:
        bundle = _load_stix2_content(filename)
    except Exception as error:
        return {'errors': [f'{filename} -  {error.__str__()}']}
    parser, args = _get_stix2_parser(
        _from_misp(bundle.objects), distribution, sharing_group_id,
        galaxies_as_tags, organisation_uuid,
        cluster_distribution, cluster_sharing_group_id
    )
    stix_parser = parser(*args)
    stix_parser.load_stix_bundle(bundle)
    stix_parser.parse_stix_bundle(single_event)
    if output_dir is None:
        output_dir = filename.parent
    if stix_parser.single_event:
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        with open(name, 'wt', encoding='utf-8') as f:
            f.write(stix_parser.misp_event.to_json(indent=4))
        return _generate_traceback(debug, stix_parser, name)
    output_names = []
    for misp_event in stix_parser.misp_events:
        output = output_dir / f'{filename.name}.{misp_event.uuid}.misp.out'
        with open(output, 'wt', encoding='utf-8') as f:
            f.write(misp_event.to_json(indent=4))
        output_names.append(output)
    return _generate_traceback(debug, stix_parser, *output_names)


################################################################################
#                        STIX CONTENT LOADING FUNCTIONS                        #
################################################################################

def _from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object['type'] in _STIX2_event_types and any(tag in stix_object.get('labels', []) for tag in _MISP_STIX_tags):
            return True
    return False


def _get_stix2_parser(from_misp: bool, *args: tuple) -> tuple:
    if from_misp:
        return InternalSTIX2toMISPParser, args[:-3]
    return ExternalSTIX2toMISPParser, args


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


################################################################################
#                            COMMAND LINE FUNCTIONS                            #
################################################################################

def _misp_to_stix(stix_args):
    collection_args = {
        'in_memory': stix_args.in_memory,
        'single_output': stix_args.single_output
    }
    if stix_args.version in ('1.1.1', '1.2'):
        stix1_args = {
            'debug': stix_args.debug, 'return_format': stix_args.format,
            'version': stix_args.version, 'namespace': stix_args.namespace,
            'org': stix_args.org, 'output_dir': stix_args.output_dir,
            'output_name': stix_args.output_name
        }
        if stix_args.level == 'attribute':
            return misp_attribute_collection_to_stix1(
                *stix_args.file, **collection_args, **stix1_args
            )
        if len(stix_args.file) == 1:
            return misp_to_stix1(stix_args.file[0], **stix1_args)
        return misp_event_collection_to_stix1(
            *stix_args.file, **collection_args, **stix1_args
        )
    stix2_args = {
        'debug': stix_args.debug, 'output_dir': stix_args.output_dir,
        'output_name': stix_args.output_name, 'version': stix_args.version
    }
    if len(stix_args.file) == 1:
        return misp_to_stix2(stix_args.file[0])
    return misp_collection_to_stix2(
        *stix_args.file, **collection_args, **stix2_args
    )


def _stix_to_misp(stix_args):
    method = stix_2_to_misp if stix_args.version == '2' else stix_1_to_misp
    results = defaultdict(dict)
    success = []
    for filename in stix_args.file:
        traceback = method(
            filename, cluster_distribution=stix_args.cluster_distribution,
            cluster_sharing_group_id=stix_args.cluster_sharing_group,
            debug=stix_args.debug, distribution=stix_args.distribution,
            galaxies_as_tags=stix_args.galaxies_as_tags,
            organisation_uuid=stix_args.org_uuid,
            output_dir=stix_args.output_dir,
            output_name=stix_args.output_name,
            sharing_group_id=stix_args.sharing_group,
            single_event=stix_args.single_output
        )
        if traceback.pop('success', 0) == 1:
            success.extend(traceback.pop('results'))
            for key, value in traceback.items():
                if isinstance(value, dict):
                    results[key].update(value)
            continue
        for field in ('errors', 'warnings'):
            if field not in traceback:
                continue
            content = traceback[field]
            if isinstance(content, list):
                results['fails'][filename.name] = content
                continue
            for identifier, values in traceback[field].items():
                results['fails'][identifier] = tuple(values)
    if success:
        results['results'] = success
    return results


################################################################################
#                              UTILITY FUNCTIONS.                              #
################################################################################

def _check_filename(default_dir: Path, default_name: str,
                    output_dir: _files_type, output_name: _files_type) -> Path:
    if output_name is None:
        return _check_output(default_dir, default_name, output_dir)
    if not isinstance(output_name, Path):
        output_name = Path(output_name).resolve()
    if output_name.is_dir():
        return output_name / default_name
    return output_name


def _check_output(
        default_dir: Path, default_name: str, output_dir: _files_type) -> Path:
    if output_dir is None:
        return default_dir / default_name
    if not isinstance(output_dir, Path):
        output_dir = Path(output_dir).resolve()
    if output_dir.is_file():
        return output_dir
    return output_dir / default_name


def _generate_traceback(debug: bool, parser, *output_names: List[Path]) -> dict:
    traceback = {'success': 1}
    if debug:
        for feature in ('errors', 'warnings'):
            brol = getattr(parser, feature)
            if brol:
                traceback[feature] = brol
    traceback['results'] = list(output_names)
    return traceback
