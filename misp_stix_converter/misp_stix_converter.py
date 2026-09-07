# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import os
import warnings
from .misp2stix.misp_to_stix1 import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser)
from .misp2stix.misp_to_stix20 import MISPtoSTIX20Parser
from .misp2stix.misp_to_stix21 import MISPtoSTIX21Parser
from .stix2misp.importparser import MISP_org_uuid
from .tools.exceptions import _reduce_input_error
from .tools.output_writing_helpers import (
    _open_output, _private_opener, _write_output)
from .tools.stix1_framing import (
    stix1_attributes_framing, stix1_framing, _create_stix_package,
    _scoped_id_namespace, _validate_namespace)
from .tools.stix1_loading_helpers import load_stix1_package
from .tools.stix1_to_misp_helpers import get_stix1_parser, is_stix1_from_misp
from .tools.stix1_writing_helpers import (
    write_campaigns, write_courses_of_action, write_events, write_indicators,
    write_observables, write_threat_actors, write_ttps, _write_raw_stix)
from .tools.stix2_loading_helpers import load_stix2_file
from .tools.stix2_to_misp_helpers import get_stix2_parser, is_stix2_from_misp
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from pymisp import MISPEvent, PyMISP, PyMISPError
from stix2.base import STIXJSONEncoder
from stix2.v20 import Bundle as Bundle_v20
from stix2.v21 import Bundle as Bundle_v21
from tempfile import TemporaryDirectory
from typing import List, Optional, Union
from urllib3.exceptions import InsecureRequestWarning
from uuid import uuid4

_default_namespace = 'https://misp-project.org'
_default_org = 'MISP'
_files_type = Union[Path, str]
_STIX1_default_format = 'xml'
_STIX1_default_version = '1.1.1'
_STIX1_features = (
    'campaigns', 'courses_of_action', 'exploit_targets',
    'indicators', 'observables', 'threat_actors', 'ttps'
)
_STIX1_valid_formats = ('json', 'xml')
_STIX1_valid_versions = ('1.1.1', '1.2')
_STIX2_default_version = '2.1'
_STIX2_valid_versions = ('2.0', '2.1')


################################################################################
#                         MISP to STIX MAIN FUNCTIONS.                         #
################################################################################

_STIX1_feature_frames: dict[str, dict[str, tuple[str, str]]] = {
    'campaigns': {
        'xml': ('    <stix:Campaigns>\n', '    </stix:Campaigns>\n'),
        'json': ('"campaigns": [', '], '),
    },
    'courses_of_action': {
        'xml': ('    <stix:Courses_Of_Action>\n', '    </stix:Courses_Of_Action>\n'),
        'json': ('"courses_of_action": [', '], '),
    },
    'exploit_targets': {
        'xml': ('    <stix:ExploitTargets>\n', '    </stix:ExploitTargets>\n'),
        'json': ('"exploit_targets": {"exploit_targets": [', ']}, '),
    },
    'indicators': {
        'xml': ('    <stix:Indicators>\n', '    </stix:Indicators>\n'),
        'json': ('"indicators": [', '], '),
    },
    'observables': {
        'xml': ('    <stix:Observables>\n', '    </stix:Observables>\n'),
        'json': ('"observables": {"observables": [', ']}, '),
    },
    'threat_actors': {
        'xml': ('    <stix:ThreatActors>\n', '    </stix:ThreatActors>\n'),
        'json': ('"threat_actors": [', '], '),
    },
    'ttps': {
        'xml': ('    <stix:TTPs>\n', '    </stix:TTPs>\n'),
        'json': ('"ttps": {"ttps": [', ']}, '),
    },
}


class AttributeCollectionHandler:
    def __init__(self, return_format: str):
        self._return_format = return_format
        self._filenames: dict[str, str] = {}

    @property
    def return_format(self) -> str:
        return self._return_format

    @property
    def features(self) -> dict:
        return self._filenames

    def set_feature(self, feature: str, stem) -> str:
        path = f'{stem}.{self._return_format}'
        self._filenames[feature] = path
        return path

    def get_filename(self, feature: str) -> str | None:
        return self._filenames.get(feature)

    def header(self, feature: str) -> str:
        return _STIX1_feature_frames[feature][self._return_format][0]

    def footer(self, feature: str) -> str:
        return _STIX1_feature_frames[feature][self._return_format][1]


def misp_attribute_collection_to_stix1(
        *input_files: List[_files_type], debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: str = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None,
        overwrite: Optional[bool] = False) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    namespace = _validate_namespace(namespace)
    with _scoped_id_namespace(namespace, org):
        parser = MISPtoSTIX1AttributesParser(org, version)
        if len(input_files) == 1:
            try:
                filename = input_files[0]
                if isinstance(filename, str):
                    filename = Path(filename).resolve()
                parser.parse_json_file(filename)
                name = _check_filename(
                    filename.parent, f'{filename.name}.out', output_dir, output_name
                )
                _write_raw_stix(
                    parser.stix_package, name, namespace, org, return_format,
                    overwrite
                )
                return _generate_traceback(debug, parser, name)
            except Exception as exception:
                return _generate_failure_traceback(
                    debug, parser, filename, exception
                )
        traceback = defaultdict(list)
        if single_output:
            stix_package = _create_stix_package(org, version)
            name = _check_filename(
                _default_output_dir(*input_files),
                _default_stix1_name(stix_package, return_format),
                output_dir, output_name
            )
            if in_memory:
                for filename in input_files:
                    try:
                        parser.parse_json_file(filename)
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
                        traceback['fails'].append(
                            _reduce_input_error(filename, exception)
                        )
                if len(traceback.get('fails', ())) < len(input_files):
                    _write_raw_stix(
                        stix_package, name, namespace, org, return_format,
                        overwrite
                    )
                    traceback.update(_generate_traceback(debug, parser, name))
                else:
                    _merge_recorded_messages(traceback, debug, parser)
                return traceback
            handler = AttributeCollectionHandler(return_format)
            # The per-feature fragments hold converted content: they live in a
            # scratch directory of their own, removed however the assembly ends
            with TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                for filename in input_files:
                    try:
                        parser.parse_json_file(filename)
                        package = parser.stix_package
                        for feature in _STIX1_features:
                            values = getattr(package, feature)
                            if values:
                                content = globals()[f'write_{feature}'](values, return_format)
                                if not content.strip():
                                    continue
                                fragment = handler.get_filename(feature)
                                if fragment is None:
                                    fragment = handler.set_feature(feature, uuid4())
                                    with open(
                                            tmp_path / fragment, 'wt',
                                            encoding='utf-8',
                                            opener=_private_opener) as f:
                                        f.write(f'{handler.header(feature)}{content}')
                                    continue
                                with open(
                                        tmp_path / fragment, 'at',
                                        encoding='utf-8',
                                        opener=_private_opener) as f:
                                    # XML elements follow each other; the items
                                    # of a JSON array need the separator the
                                    # writers only put between the items of one
                                    # input file
                                    f.write(
                                        content if return_format == 'xml'
                                        else f', {content}'
                                    )
                    except Exception as exception:
                        traceback['fails'].append(
                            _reduce_input_error(filename, exception)
                        )
                if len(traceback.get('fails', ())) < len(input_files):
                    header, _, footer = stix1_attributes_framing(
                        namespace, org, return_format, stix_package.version
                    )
                    with _open_output(name, overwrite=overwrite) as output:
                        output.write(header)
                        for feature, fragment in handler.features.items():
                            with open(tmp_path / fragment, 'rt', encoding='utf-8') as current:
                                content = current.read()
                            current_footer = handler.footer(feature)
                            if return_format == 'json' and feature == list(handler.features)[-1]:
                                current_footer = current_footer[:-2]
                            output.write(f'{content}{current_footer}')
                        output.write(footer)
                    traceback.update(_generate_traceback(debug, parser, name))
                else:
                    _merge_recorded_messages(traceback, debug, parser)
            return traceback
        output_names = []
        for filename in input_files:
            try:
                if isinstance(filename, str):
                    filename = Path(filename).resolve()
                parser.parse_json_file(filename)
                name = _check_output(
                    filename.parent, f'{filename.name}.out', output_dir
                )
                _write_raw_stix(
                    parser.stix_package, name, namespace, org, return_format,
                    overwrite
                )
                output_names.append(name)
            except Exception as exception:
                traceback['fails'].append(_reduce_input_error(filename, exception))
        if output_names:
            traceback.update(_generate_traceback(debug, parser, *output_names))
        else:
            _merge_recorded_messages(traceback, debug, parser)
        return traceback


def misp_event_collection_to_stix1(
        *input_files: List[_files_type], debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: str = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None,
        overwrite: Optional[bool] = False) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    namespace = _validate_namespace(namespace)
    with _scoped_id_namespace(namespace, org):
        _write_args = (namespace, org, return_format, overwrite)
        parser = MISPtoSTIX1EventsParser(org, version)
        if len(input_files) == 1:
            filename = input_files[0]
            try:
                if not isinstance(filename, Path):
                    filename = Path(filename).resolve()
                parser.parse_json_file(filename)
                name = _check_filename(
                    filename.parent, f'{filename.name}.out', output_dir, output_name
                )
                _write_raw_stix(parser.stix_package, name, *_write_args)
                return _generate_traceback(debug, parser, name)
            except Exception as exception:
                return _generate_failure_traceback(
                    debug, parser, filename, exception
                )
        traceback = defaultdict(list)
        if single_output:
            stix_package = _create_stix_package(org, version, header=False)
            name = _check_filename(
                _default_output_dir(*input_files),
                _default_stix1_name(stix_package, return_format),
                output_dir, output_name
            )
            if in_memory:
                for filename in input_files:
                    try:
                        if not isinstance(filename, Path):
                            filename = Path(filename).resolve()
                        parser.parse_json_file(filename)
                        if parser.stix_package.related_packages is not None:
                            for related_package in parser.stix_package.related_packages:
                                stix_package.add_related_package(related_package)
                        else:
                            stix_package.add_related_package(parser.stix_package)
                    except Exception as exception:
                        traceback['fails'].append(
                            _reduce_input_error(filename, exception)
                        )
                if len(traceback.get('fails', ())) < len(input_files):
                    _write_raw_stix(stix_package, name, *_write_args)
                    traceback.update(_generate_traceback(debug, parser, name))
                else:
                    _merge_recorded_messages(traceback, debug, parser)
                return traceback
            header, separator, footer = stix1_framing(
                namespace, org, return_format, stix_package.version
            )
            written = False
            with _open_output(name, overwrite=overwrite) as output:
                filename = input_files[0]
                try:
                    if not isinstance(filename, Path):
                        filename = Path(filename).resolve()
                    parser.parse_json_file(filename)
                    content = write_events(parser.stix_package, return_format)
                    output.write(f'{header}{content}')
                    written = True
                except Exception as exception:
                    traceback['fails'].append(
                        _reduce_input_error(filename, exception)
                    )
                for filename in input_files[1:]:
                    try:
                        if not isinstance(filename, Path):
                            filename = Path(filename).resolve()
                        parser.parse_json_file(filename)
                        content = write_events(parser.stix_package, return_format)
                        output.write(
                            f'{separator}{content}' if written else content
                        )
                        written = True
                    except Exception as exception:
                        traceback['fails'].append(
                            _reduce_input_error(filename, exception)
                        )
                if written:
                    output.write(footer)
                else:
                    # No input file converted: the destination keeps whatever it
                    # held rather than taking a header and a footer alone
                    output.discard()
            if written:
                traceback.update(_generate_traceback(debug, parser, name))
            else:
                _merge_recorded_messages(traceback, debug, parser)
            return traceback
        output_names = []
        for filename in input_files:
            try:
                if not isinstance(filename, Path):
                    filename = Path(filename).resolve()
                parser.parse_json_file(filename)
                name = _check_output(
                    filename.parent, f'{filename.name}.out', output_dir
                )
                _write_raw_stix(parser.stix_package, name, *_write_args)
                output_names.append(name)
            except Exception as exception:
                traceback['fails'].append(_reduce_input_error(filename, exception))
        if output_names:
            traceback.update(_generate_traceback(debug, parser, *output_names))
        else:
            _merge_recorded_messages(traceback, debug, parser)
        return traceback


def misp_collection_to_stix2(
        *input_files: List[_files_type], debug: Optional[bool] = False,
        version: Optional[str] = _STIX2_default_version,
        in_memory: Optional[bool] = False,
        single_output: Optional[bool] = False,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None,
        overwrite: Optional[bool] = False) -> dict:
    if version not in _STIX2_valid_versions:
        version = _STIX2_default_version
    parser = MISPtoSTIX21Parser() if version == '2.1' else MISPtoSTIX20Parser()
    if len(input_files) == 1:
        filename = input_files[0]
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_file(filename)
            name = _check_filename(
                filename.parent, f'{filename.name}.out', output_dir, output_name
            )
            _write_output(
                name, parser.bundle.serialize(indent=4), overwrite=overwrite
            )
            return _generate_traceback(debug, parser, name)
        except Exception as exception:
            return _generate_failure_traceback(
                debug, parser, filename, exception
            )
    traceback = defaultdict(list)
    if single_output:
        if in_memory:
            for filename in input_files:
                try:
                    if not isinstance(filename, Path):
                        filename = Path(filename).resolve()
                    parser.parse_json_file(filename)
                except Exception as exception:
                    traceback['fails'].append(_reduce_input_error(filename, exception))
            if len(traceback.get('fails', ())) < len(input_files):
                bundle = parser.bundle
                name = _check_filename(
                    _default_output_dir(*input_files),
                    f"{bundle.id.split('--')[1]}.stix"
                    f"{version.replace('.', '')}.json",
                    output_dir, output_name
                )
                _write_output(
                    name, bundle.serialize(indent=4), overwrite=overwrite
                )
                traceback.update(_generate_traceback(debug, parser, name))
            else:
                _merge_recorded_messages(traceback, debug, parser)
            return traceback
        bundle = Bundle_v21() if version == '2.1' else Bundle_v20()
        name = _check_filename(
            _default_output_dir(*input_files),
            f"{bundle.id.split('--')[1]}.stix{version.replace('.', '')}.json",
            output_dir, output_name
        )
        with _open_output(name, overwrite=overwrite) as output:
            output.write(
                f'{bundle.serialize(indent=4)[:-2]},\n    "objects": [\n'
            )
            written = False
            try:
                filename = input_files[0]
                if not isinstance(filename, Path):
                    filename = Path(filename).resolve()
                parser.parse_json_file(filename)
                stix_objects = json.dumps(
                    [parser.fetch_stix_objects], cls=STIXJSONEncoder, indent=4
                )
                output.write(stix_objects[8:-8])
                written = True
            except Exception as exception:
                traceback['fails'].append(_reduce_input_error(filename, exception))
            for filename in input_files[1:]:
                try:
                    if not isinstance(filename, Path):
                        filename = Path(filename).resolve()
                    parser.parse_json_file(filename)
                    stix_objects = json.dumps(
                        [parser.fetch_stix_objects], cls=STIXJSONEncoder,
                        indent=4
                    )
                    separator = ',\n' if written else ''
                    output.write(f"{separator}{stix_objects[8:-8]}")
                    written = True
                except Exception as exception:
                    traceback['fails'].append(
                        _reduce_input_error(filename, exception)
                    )
            if written:
                output.write('\n    ]\n}')
            else:
                # Nothing came out of any input file: the destination keeps
                # whatever it held rather than taking a bundle header alone
                output.discard()
        if written:
            traceback.update(_generate_traceback(debug, parser, name))
        else:
            _merge_recorded_messages(traceback, debug, parser)
        return traceback
    output_names = []
    for filename in input_files:
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_file(filename)
            name = _check_output(
                filename.parent, f'{filename.name}.out', output_dir
            )
            _write_output(
                name, parser.bundle.serialize(indent=4), overwrite=overwrite
            )
            output_names.append(name)
        except Exception as exception:
            traceback['fails'].append(_reduce_input_error(filename, exception))
    if output_names:
        traceback.update(_generate_traceback(debug, parser, *output_names))
    else:
        _merge_recorded_messages(traceback, debug, parser)
    return traceback


def misp_to_stix1(
        filename: _files_type, debug: Optional[bool] = False,
        return_format: Optional[str] = _STIX1_default_format,
        namespace: str = _default_namespace,
        org: Optional[str] = _default_org,
        version: Optional[str] = _STIX1_default_version,
        output_dir: Optional[_files_type] = None,
        output_name: Optional[_files_type] = None,
        overwrite: Optional[bool] = False) -> dict:
    if return_format not in _STIX1_valid_formats:
        return_format = _STIX1_default_format
    if version not in _STIX1_valid_versions:
        version = _STIX1_default_version
    namespace = _validate_namespace(namespace)
    with _scoped_id_namespace(namespace, org):
        parser = MISPtoSTIX1EventsParser(org, version)
        try:
            if not isinstance(filename, Path):
                filename = Path(filename).resolve()
            parser.parse_json_file(filename)
            name = _check_filename(
                filename.parent, f'{filename.name}.out', output_dir, output_name
            )
            _write_raw_stix(
                parser.stix_package, name, namespace, org, return_format, overwrite
            )
        except Exception as exception:
            return _generate_failure_traceback(
                debug, parser, filename, exception
            )
        return _generate_traceback(debug, parser, name)


def misp_to_stix2(filename: _files_type, debug: Optional[bool] = False,
                  version: Optional[str] = _STIX2_default_version,
                  output_dir: Optional[_files_type] = None,
                  output_name: Optional[_files_type] = None,
                  overwrite: Optional[bool] = False) -> dict:
    if version not in _STIX2_valid_versions:
        version = _STIX2_default_version
    parser = MISPtoSTIX21Parser() if version == '2.1' else MISPtoSTIX20Parser()
    try:
        if not isinstance(filename, Path):
            filename = Path(filename).resolve()
        parser.parse_json_file(filename)
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        _write_output(
            name, json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4),
            overwrite=overwrite
        )
    except Exception as exception:
        return _generate_failure_traceback(debug, parser, filename, exception)
    return _generate_traceback(debug, parser, name)


################################################################################
#                         STIX to MISP MAIN FUNCTIONS.                         #
################################################################################

def stix_1_to_misp(filename: _files_type,
                   classification: Optional[str] = None,
                   cluster_distribution: Optional[int] = 0,
                   cluster_sharing_group_id: Optional[int] = None,
                   debug: Optional[bool] = False,
                   distribution: Optional[int] = 0,
                   force_contextual_data: Optional[bool] = False,
                   galaxies_as_tags: Optional[bool] = False,
                   max_size: Optional[int] = None,
                   organisation_uuid: Optional[str] = MISP_org_uuid,
                   output_dir: Optional[_files_type]=None,
                   output_name: Optional[_files_type]=None,
                   overwrite: Optional[bool] = False,
                   producer: Optional[str] = None,
                   sharing_group_id: Optional[int] = None,
                   single_event: Optional[bool] = False,
                   title: Optional[str] = None) -> dict:
    from_misp = _classification_as_from_misp(classification)
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    try:
        stix_package = load_stix1_package(filename, max_size=max_size)
        detected = is_stix1_from_misp(stix_package)
        parser, args = get_stix1_parser(
            detected if from_misp is None else from_misp, distribution,
            sharing_group_id, title, producer, force_contextual_data,
            galaxies_as_tags, single_event, organisation_uuid,
            cluster_distribution, cluster_sharing_group_id
        )
        stix_parser = parser()
        stix_parser.load_stix_package(stix_package)
        _handle_classification_warning(stix_parser, from_misp, detected)
        stix_parser.parse_stix_package(**args)
    except Exception as error:
        return {'errors': [_reduce_input_error(filename, error)]}
    if stix_parser.single_event:
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        _write_output(
            name, stix_parser.misp_event.to_json(indent=4),
            overwrite=overwrite
        )
        return _generate_traceback(debug, stix_parser, name)
    directory = _check_output_dir(filename.parent, output_dir)
    output_names = []
    for misp_event in stix_parser.misp_events:
        output = directory / f'{filename.name}.{misp_event.uuid}.misp.out'
        _write_output(
            output, misp_event.to_json(indent=4), overwrite=overwrite
        )
        output_names.append(output)
    return _generate_traceback(debug, stix_parser, *output_names)


def stix1_to_misp_instance(misp: PyMISP, filename: _files_type,
                           classification: Optional[str] = None,
                           cluster_distribution: Optional[int] = 0,
                           cluster_sharing_group_id: Optional[int] = None,
                           debug: Optional[bool] = False,
                           distribution: Optional[int] = 0,
                           force_contextual_data: Optional[bool] = False,
                           galaxies_as_tags: Optional[bool] = False,
                           max_size: Optional[int] = None,
                           organisation_uuid: Optional[str] = MISP_org_uuid,
                           producer: Optional[str] = None,
                           sharing_group_id: Optional[int] = None,
                           single_event: Optional[bool] = False,
                           title: Optional[str] = None) -> dict:
    from_misp = _classification_as_from_misp(classification)
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    try:
        stix_package = load_stix1_package(filename, max_size=max_size)
        detected = is_stix1_from_misp(stix_package)
        parser, args = get_stix1_parser(
            detected if from_misp is None else from_misp, distribution,
            sharing_group_id, title, producer, force_contextual_data,
            galaxies_as_tags, single_event, organisation_uuid,
            cluster_distribution, cluster_sharing_group_id
        )
        stix_parser = parser()
        stix_parser.load_stix_package(stix_package)
        _handle_classification_warning(stix_parser, from_misp, detected)
        stix_parser.parse_stix_package(**args)
    except Exception as error:
        return {'errors': [_reduce_input_error(filename, error)]}
    if stix_parser.single_event:
        misp_event = misp.add_event(stix_parser.misp_event, pythonify=True)
        if not isinstance(misp_event, MISPEvent):
            return _generate_traceback(
                debug, stix_parser, errors={
                    stix_parser.misp_event.uuid: misp_event['errors'][1]['message']
                }
            )
        return _generate_traceback(debug, stix_parser, misp_event.id)
    event_ids = []
    errors = {}
    for event in stix_parser.misp_events:
        misp_event = misp.add_event(event, pythonify=True)
        if not isinstance(misp_event, MISPEvent):
            errors[event.uuid] = misp_event['errors'][1]['message']
            continue
        event_ids.append(misp_event.id)
    return _generate_traceback(
        debug, stix_parser, *event_ids, errors=list(errors)
    )


def stix_2_to_misp(filename: _files_type,
                   classification: Optional[str] = None,
                   cluster_distribution: Optional[int] = 0,
                   cluster_sharing_group_id: Optional[int] = None,
                   debug: Optional[bool] = False,
                   distribution: Optional[int] = 0,
                   force_contextual_data: Optional[bool] = False,
                   galaxies_as_tags: Optional[bool] = False,
                   max_size: Optional[int] = None,
                   organisation_uuid: Optional[str] = MISP_org_uuid,
                   output_dir: Optional[_files_type]=None,
                   output_name: Optional[_files_type]=None,
                   overwrite: Optional[bool] = False,
                   producer: Optional[str] = None,
                   sharing_group_id: Optional[int] = None,
                   single_event: Optional[bool] = False,
                   title: Optional[str] = None) -> dict:
    from_misp = _classification_as_from_misp(classification)
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    try:
        bundle = load_stix2_file(filename, max_size=max_size)
        detected = is_stix2_from_misp(getattr(bundle, 'objects', []))
        parser, args = get_stix2_parser(
            detected if from_misp is None else from_misp, distribution,
            sharing_group_id, title, producer, force_contextual_data,
            galaxies_as_tags, single_event, organisation_uuid,
            cluster_distribution, cluster_sharing_group_id
        )
        stix_parser = parser()
        stix_parser.load_stix_bundle(bundle)
        _handle_classification_warning(stix_parser, from_misp, detected)
        stix_parser.parse_stix_bundle(**args)
    except Exception as error:
        return {'errors': [_reduce_input_error(filename, error)]}
    if stix_parser.single_event:
        name = _check_filename(
            filename.parent, f'{filename.name}.out', output_dir, output_name
        )
        _write_output(
            name, stix_parser.misp_event.to_json(indent=4),
            overwrite=overwrite
        )
        return _generate_traceback(debug, stix_parser, name)
    directory = _check_output_dir(filename.parent, output_dir)
    output_names = []
    for misp_event in stix_parser.misp_events:
        output = directory / f'{filename.name}.{misp_event.uuid}.misp.out'
        _write_output(
            output, misp_event.to_json(indent=4), overwrite=overwrite
        )
        output_names.append(output)
    return _generate_traceback(debug, stix_parser, *output_names)


def stix2_to_misp_instance(misp: PyMISP, filename: _files_type,
                           classification: Optional[str] = None,
                           cluster_distribution: Optional[int] = 0,
                           cluster_sharing_group_id: Optional[int] = None,
                           debug: Optional[bool] = False,
                           distribution: Optional[int] = 0,
                           force_contextual_data: Optional[bool] = False,
                           galaxies_as_tags: Optional[bool] = False,
                           max_size: Optional[int] = None,
                           organisation_uuid: Optional[str] = MISP_org_uuid,
                           producer: Optional[str] = None,
                           sharing_group_id: Optional[int] = None,
                           single_event: Optional[bool] = False,
                           title: Optional[str] = None) -> dict:
    from_misp = _classification_as_from_misp(classification)
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    try:
        bundle = load_stix2_file(filename, max_size=max_size)
        detected = is_stix2_from_misp(getattr(bundle, 'objects', []))
        parser, args = get_stix2_parser(
            detected if from_misp is None else from_misp, distribution,
            sharing_group_id, title, producer, force_contextual_data,
            galaxies_as_tags, single_event, organisation_uuid,
            cluster_distribution, cluster_sharing_group_id
        )
        stix_parser = parser()
        stix_parser.load_stix_bundle(bundle)
        _handle_classification_warning(stix_parser, from_misp, detected)
        stix_parser.parse_stix_bundle(**args)
    except Exception as error:
        return {'errors': [_reduce_input_error(filename, error)]}
    if stix_parser.single_event:
        misp_event = misp.add_event(stix_parser.misp_event, pythonify=True)
        if not isinstance(misp_event, MISPEvent):
            return _generate_traceback(
                debug, stix_parser, errors={
                    stix_parser.misp_event.uuid: misp_event['errors'][1]['message']
                }
            )
        return _generate_traceback(debug, stix_parser, misp_event.id)
    event_ids = []
    errors = {}
    for event in stix_parser.misp_events:
        misp_event = misp.add_event(event, pythonify=True)
        if not isinstance(misp_event, MISPEvent):
            errors[event.uuid] = misp_event['errors'][1]['message']
            continue
        event_ids.append(misp_event.id)
    return _generate_traceback(
        debug, stix_parser, *event_ids, errors=list(errors)
    )


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
            'output_name': stix_args.output_name,
            'overwrite': stix_args.overwrite
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
        'output_name': stix_args.output_name,
        'overwrite': stix_args.overwrite, 'version': stix_args.version
    }
    if len(stix_args.file) == 1:
        return misp_to_stix2(stix_args.file[0], **stix2_args)
    return misp_collection_to_stix2(
        *stix_args.file, **collection_args, **stix2_args
    )


@contextmanager
def _suppressed_insecure_request_warnings(verify_cert: Union[bool, str]):
    # `verify_cert` is what PyMISP's `ssl` argument takes: a boolean, or a
    # CA bundle path (truthy, so verification stays on and nothing is hidden).
    # Deliberately unverified connections would flood stderr with one
    # `InsecureRequestWarning` per request: quiet exactly that warning, only
    # while the MISP connection is in use, leaving the filters as they were.
    if verify_cert:
        yield
        return
    with warnings.catch_warnings():
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)
        yield


def _flag_or_env(flag_value: Optional[str], variable: str) -> Optional[str]:
    # Flags beat environment beats config file: `MISP_URL` / `MISP_API_KEY`
    # only fill in flags the operator left out, keeping the authentication key
    # off `argv` and out of shell history (empty variables count as unset)
    if flag_value is not None:
        return flag_value
    return os.environ.get(variable) or None


def _stix_to_misp(args):
    url = _flag_or_env(args.url, 'MISP_URL')
    api_key = _flag_or_env(args.api_key, 'MISP_API_KEY')
    if args.config is None and url is None and api_key is None:
        return _process_stix_to_misp_files(args)
    try:
        if url is not None and api_key is not None:
            verify_cert = not args.skip_ssl
            with _suppressed_insecure_request_warnings(verify_cert):
                misp = PyMISP(url, api_key, verify_cert)
                return _process_stix_to_misp_instance(misp, args)
        elif args.config is not None:
            try:
                with open(args.config, 'rt', encoding='utf-8') as f:
                    config = json.load(f)
                verify_cert = config['verify_cert']
                with _suppressed_insecure_request_warnings(verify_cert):
                    misp = PyMISP(
                        config['url'], config['api_key'], verify_cert
                    )
                    return _process_stix_to_misp_instance(misp, args)
            except (FileNotFoundError, KeyError, json.JSONDecodeError):
                msg = 'Unable to read configuration file to connect to MISP -'
        else:
            msg = 'Missing URL or API key to connect to MISP instance -'
    except PyMISPError as error:
        msg = f'Unable to connect to MISP instance ({error}) -'
    print(f'{msg} Saving MISP results into files instead.')
    return _process_stix_to_misp_files(args)


def _max_size_from_args(args) -> Optional[int]:
    # the command line names a size in MB, the library a size in bytes
    if args.max_input_size is None:
        return None
    return args.max_input_size * 1024 * 1024


def _process_stix_to_misp_files(args) -> dict:
    results = defaultdict(dict)
    success = []
    method = _get_stix_conversion_method(args.version)
    kwargs = {
        'classification': args.classification,
        'cluster_distribution': args.cluster_distribution,
        'cluster_sharing_group_id': args.cluster_sharing_group,
        'debug': args.debug,
        'distribution': args.distribution,
        'force_contextual_data': not args.no_force_contextual_data,
        'galaxies_as_tags': args.galaxies_as_tags,
        'max_size': _max_size_from_args(args),
        'output_dir': args.output_dir,
        'organisation_uuid': args.org_uuid,
        'output_name': args.output_name,
        'overwrite': args.overwrite,
        'producer': args.producer,
        'sharing_group_id': args.sharing_group,
        'single_event': args.single_event,
        'title': args.title
    }
    for filename in args.file:
        traceback = method(filename, **kwargs)
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
            # errors and warnings key on the same identifier: gather them
            # instead of letting the warnings overwrite the errors
            for identifier, values in content.items():
                results['fails'][identifier] = (
                    *results['fails'].get(identifier, ()), *values
                )
    if success:
        results['results'] = success
    return results


def _process_stix_to_misp_instance(misp: PyMISP, args) -> dict:
    if args.org_uuid is None:
        my_user = misp.get_user()
        args.org_uuid = my_user['Organisation']['uuid']
    results = defaultdict(dict)
    success = []
    method = _get_stix_ingestion_method(args.version)
    kwargs = {
        'classification': args.classification,
        'cluster_distribution': args.cluster_distribution,
        'cluster_sharing_group_id': args.cluster_sharing_group,
        'debug': args.debug,
        'distribution': args.distribution,
        'force_contextual_data': not args.no_force_contextual_data,
        'galaxies_as_tags': args.galaxies_as_tags,
        'max_size': _max_size_from_args(args),
        'organisation_uuid': args.org_uuid,
        'producer': args.producer,
        'sharing_group_id': args.sharing_group,
        'single_event': args.single_event,
        'title': args.title
    }
    for filename in args.file:
        traceback = method(misp, filename, **kwargs)
        if traceback.pop('success', 0) == 1:
            success.extend(traceback.pop('results'))
            for key, value in traceback.items():
                if isinstance(value, dict):
                    results[key].update(value)
            continue
        if 'pymisp_errors' in traceback:
            results['pymisp_errors'].update(traceback['pymisp_errors'])
        for field in ('errors', 'warnings'):
            if field not in traceback:
                continue
            content = traceback[field]
            if isinstance(content, list):
                results['fails'][filename.name] = content
                continue
            # errors and warnings key on the same identifier: gather them
            # instead of letting the warnings overwrite the errors
            for identifier, values in content.items():
                results['fails'][identifier] = (
                    *results['fails'].get(identifier, ()), *values
                )
    if success:
        results['event_ids'] = success
    return results


################################################################################
#                              UTILITY FUNCTIONS.                              #
################################################################################

def _as_path(location: _files_type) -> Path:
    # Every funnel takes the `Path` or the `str` the parameters document, so
    # none of them can leave a `str` for a caller to join a name onto
    return location if isinstance(location, Path) else Path(location).resolve()


def _check_filename(default_dir: Path, default_name: str,
                    output_dir: _files_type, output_name: _files_type) -> Path:
    if output_name is None:
        return _check_output(default_dir, default_name, output_dir)
    output_name = _as_path(output_name)
    if output_name.is_dir():
        return output_name / default_name
    return _ensure_directory(output_name.parent) / output_name.name


def _check_output(
        default_dir: Path, default_name: str, output_dir: _files_type) -> Path:
    if output_dir is None:
        return default_dir / default_name
    output_dir = _as_path(output_dir)
    if output_dir.is_file():
        return output_dir
    return _ensure_directory(output_dir) / default_name


def _check_output_dir(default_dir: Path, output_dir: _files_type) -> Path:
    # Where the import entries write one file per MISP event. Unlike
    # `_check_output` the destination can only be a directory - a single file
    # cannot hold several events - so a location the caller named is created
    # rather than read as an output file, and how many events a document
    # yields is its own shape rather than a caller parameter, so it cannot
    # decide whether a documented parameter type works
    if output_dir is None:
        return default_dir
    return _ensure_directory(_as_path(output_dir))


def _default_output_dir(*input_files: _files_type) -> Path:
    # Where a collection export writes when the caller named no location: the
    # directory the input files come from, like the single input entries do.
    # Never the installed package tree - a library has no business using its
    # own installation directory as an output or scratch area
    filename = input_files[0]
    if not isinstance(filename, Path):
        filename = Path(filename)
    return filename.resolve().parent


def _default_stix1_name(stix_package, return_format: str) -> str:
    # `<orgname>:STIXPackage-<uuid>` is the package id, not a filename: the
    # organisation prefix goes with the `:` separator, which Windows and SMB
    # shares reject
    return f"{stix_package.id_.split(':')[-1]}.stix1.{return_format}"


def _ensure_directory(directory: Path) -> Path:
    # An output location the caller named is a request: a directory that does
    # not exist yet is created rather than failing at write time
    directory.mkdir(parents=True, exist_ok=True)
    return directory


_CLASSIFICATION_VALUES = ('internal', 'external')


def _classification_as_from_misp(classification: Optional[str]) -> Optional[bool]:
    if classification is None:
        return None
    if classification not in _CLASSIFICATION_VALUES:
        raise ValueError(
            f"Invalid classification value: '{classification}' - "
            "must be either 'internal' or 'external'."
        )
    return classification == 'internal'


def _handle_classification_warning(
        parser, from_misp: Optional[bool], detected: bool):
    if from_misp is None:
        if detected:
            parser._add_warning(
                'The Internal parser was selected from the document content '
                'itself. Use the `classification` parameter to make this '
                'choice explicit.'
            )
    elif from_misp != detected:
        parser._add_warning(
            'The STIX document content is detected as '
            f"{'internal' if detected else 'external'}, but is parsed as "
            f"{'internal' if from_misp else 'external'} as requested with "
            'the `classification` parameter.'
        )


def _generate_failure_traceback(
        debug: bool, parser, filename: _files_type,
        exception: Exception) -> dict:
    return _merge_recorded_messages(
        {'fails': [_reduce_input_error(filename, exception)]}, debug, parser
    )


def _generate_traceback(
        debug: bool, parser, *output_names: tuple, errors: dict = {}) -> dict:
    traceback = {'pymisp_errors': errors} if errors else {'success': 1}
    _merge_recorded_messages(traceback, debug, parser)
    traceback['results'] = list(output_names)
    return traceback


def _merge_recorded_messages(traceback: dict, debug: bool, parser) -> dict:
    # Warnings and errors surface regardless of `debug`: a conversion that
    # dropped content never reports a bare success - nor a bare failure, since
    # what the parser recorded before a crash is part of what explains it.
    # `debug` only selects the errors detail - warnings are reported in full
    # either way
    warnings = parser.warnings
    if warnings:
        traceback['warnings'] = warnings
    if parser.errors:
        # `parser.errors` is the parser's own `defaultdict` - copy it, so a
        # caller looking up an identifier neither aliases nor grows it
        traceback['errors'] = (
            dict(parser.errors) if debug else _summarise_errors(parser.errors)
        )
    return traceback


def _get_stix_conversion_method(version):
    if version == '2':
        return stix_2_to_misp
    return stix_1_to_misp


def _get_stix_ingestion_method(version):
    if version == '2':
        return stix2_to_misp_instance
    return stix1_to_misp_instance


_ERRORS_SUMMARY_LIMIT = 10


def _summarise_errors(errors: dict) -> dict:
    # Default reporting: one entry per distinct message, capped - a single
    # document can produce an error per object it carries - with the number
    # of remaining messages and where to get them. Messages carrying no
    # object id are indistinguishable, so how many times each happened is
    # part of the signal: hundreds of objects dropped the same way must not
    # read like one
    summary = {}
    for identifier, messages in errors.items():
        occurrences = Counter(messages)
        distinct = [
            message if occurrence == 1 else f'{message} ({occurrence} times)'
            for message, occurrence in occurrences.items()
        ]
        remaining = len(distinct) - _ERRORS_SUMMARY_LIMIT
        if remaining > 0:
            distinct = distinct[:_ERRORS_SUMMARY_LIMIT]
            distinct.append(
                f'... and {remaining} more error'
                f"{'s' if remaining > 1 else ''} - use the debug option "
                'to get the full list'
            )
        summary[identifier] = distinct
    return summary
