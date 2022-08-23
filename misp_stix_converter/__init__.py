__version__ = '2.4.161'

import argparse
import sys
from .misp_stix_mapping import Mapping
from .misp2stix import *
from .misp_stix_converter import (
    misp_attribute_collection_to_stix1, misp_collection_to_stix2_0, misp_collection_to_stix2_1,
    misp_event_collection_to_stix1, misp_to_stix1, misp_to_stix2_0, misp_to_stix2_1)
from .misp_stix_converter import (
    _get_campaigns, _get_courses_of_action, _get_events, _get_indicators,
    _get_observables, _get_threat_actors, _get_ttps)
from .misp_stix_converter import (
    _get_campaigns_footer, _get_courses_of_action_footer, _get_indicators_footer,
    _get_observables_footer, _get_threat_actors_footer, _get_ttps_footer)
from .misp_stix_converter import (
    _get_campaigns_header, _get_courses_of_action_header, _get_indicators_header,
    _get_observables_header, _get_threat_actors_header, _get_ttps_header)
from .stix2misp import *
from pathlib import Path
from uuid import uuid4


def _process_arguments(stix_args):
    if stix_args.version in ('1.1.1', '1.2'):
        if stix_args.feature == 'attribute':
            if len(stix_args.file) == 1:
                output = f'{stix_args.file[0]}.out'
                status = misp_attribute_collection_to_stix1(
                    output,
                    stix_args.file[0],
                    return_format = stix_args.format,
                    version = stix_args.version,
                    in_memory = not stix_args.tmp_files,
                    namespace = stix_args.namespace,
                    org = stix_args.org
                )
                if status != 1:
                    sys.exit(f'Error while processing {stix_args.file[0]} - status code = {status}')
                return output
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
                output = f'{filename}.out'
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
            filename = stix_args.file[0]
            status = misp_to_stix1(
                filename,
                stix_args.format,
                stix_args.version,
                namespace = stix_args.namespace,
                org = stix_args.org
            )
            if status != 1:
                sys.exit(f'Error while processing {filename} - status code = {status}')
            return f'{filename}.out'
        if stix_args.single_output:
            output = stix_args.output_dir / f'{uuid4()}.stix1.{stix_args.format}'
            status = misp_event_collection_to_stix1(
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
            status = misp_to_stix1(
                filename,
                stix_args.format,
                stix_args.version,
                namespace = stix_args.namespace,
                version = stix_args.version
            )
            if status == 1:
                results.append(f'{filename}.out')
            else:
                print(f'Error while processing {filename} - status code = {status}', file=sys.stderr)
        return results, 1
    if len(stix_args.file) == 1:
        filename = stix_args.file[0]
        status = misp_to_stix2_0(filename) if stix_args.version == '2.0' else misp_to_stix2_1(filename)
        if status != 1:
            sys.exit(f'Error while processing {filename} - status code = {status}')
        return f'{filename}.out'
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
    results = []
    method = misp_to_stix2_0 if stix_args.version == '2.0' else misp_to_stix2_1
    for filename in stix_args.file:
        status = method(filename)
        if status == 1:
            results.append(f'{filename}.out')
        else:
            print(f'Error while processing {filename} - status code = {status}', file=sys.stderr)
    return results


def main():
    parser = argparse.ArgumentParser(description='Convert MISP <-> STIX')
    # feature_parser = parser.add_mutually_exclusive_group(required=True)
    # feature_parser.add_argument('-e', '--export', action='store_true', help='Export MISP to STIX.')
    # feature_parser.add_argument('-i', '--import', action='store_true', help='Import STIX to MISP.')
    parser.add_argument('-v', '--version', choices=['1.1.1', '1.2', '2.0', '2.1'], help='STIX version.')
    parser.add_argument('-f', '--file', nargs='+', help='Path to the file(s) to convert.')
    parser.add_argument('-s', '--single_output', action='store_true', help='Produce only one result file (in case of multiple input file).')
    parser.add_argument('-t', '--tmp_files', action='store_true', help='Store result in file (in case of multiple result files) instead of keeping it in memory only.')
    stix1_parser = parser.add_argument_group('STIX 1 specific parameters')
    stix1_parser.add_argument('--feature', default='event', choices=['attribute', 'event'], help='MISP data structure level.')
    stix1_parser.add_argument('--format', default='xml', choices=['json', 'xml'], help='STIX 1 format.')
    stix1_parser.add_argument('-n', '--namespace', default='https://misp-project.org', help='Namespace to be used in the STIX 1 header.')
    stix1_parser.add_argument('-o', '--org', default='MISP', help='Organisation name to be used in the STIX 1 header.')
    stix_args = parser.parse_args()
    stix_args.file = [Path(filename).resolve() for filename in stix_args.file]
    stix_args.output_dir = stix_args.file[0].parent
    results = _process_arguments(stix_args)
    if isinstance(results, list):
        files = '\n - '.join(str(result) for result in results)
        print(f"Successfully processed your {'files' if len(results) > 1 else 'file'}. Results available in:\n - {files}")
    else:
        print(f"Successfully processed your {'files' if len(stix_args.file) > 1 else 'file'}. Results available in {results}")
