__version__ = '2.4.169'

import argparse
import sys
from .misp_stix_mapping import Mapping
from .misp2stix import *
from .misp_stix_converter import (
    misp_attribute_collection_to_stix1, misp_collection_to_stix2_0, misp_collection_to_stix2_1,
    misp_event_collection_to_stix1, misp_to_stix1, misp_to_stix2_0, misp_to_stix2_1,
    stix_1_to_misp, stix_2_to_misp)
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


def main():
    parser = argparse.ArgumentParser(description='Convert MISP <-> STIX')

    feature_parser = parser.add_mutually_exclusive_group(required=True)
    feature_parser.add_argument(
        '-e', '--export', action='store_true', help='Export MISP to STIX.'
    )
    feature_parser.add_argument(
        '-i', '--import', action='store_true', help='Import STIX to MISP.'
    )

    parser.add_argument(
        '-v', '--version', choices=['1.1.1', '1.2', '2.0', '2.1'],
        required=True, help='STIX version.'
    )
    parser.add_argument(
        '-f', '--file', nargs='+', type=Path, required=True,
        help='Path to the file(s) to convert.'
    )
    parser.add_argument(
        '-s', '--single_output', action='store_true',
        help='Produce only one result file (in case of multiple input file).'
    )
    parser.add_argument(
        '-t', '--tmp_files', action='store_true',
        help='Store result in file (in case of multiple result files) '
             'instead of keeping it in memory only.'
    )
    parser.add_argument(
        '-o', '--output_name', type=Path, help='Output file name'
    )
    parser.add_argument(
        '--output_dir', type=Path,
        help='Output path for the conversion results.'
    )

    stix1_parser = parser.add_argument_group('STIX 1 specific parameters')
    stix1_parser.add_argument(
        '--feature', default='event', choices=['attribute', 'event'],
        help='MISP data structure level.'
    )
    stix1_parser.add_argument(
        '--format', default='xml', choices=['json', 'xml'],
        help='STIX 1 format.'
    )
    stix1_parser.add_argument(
        '-n', '--namespace', default='https://misp-project.org',
        help='Namespace to be used in the STIX 1 header.'
    )
    stix1_parser.add_argument(
        '-org', default='MISP',
        help='Organisation name to be used in the STIX 1 header.'
    )

    stix_args = parser.parse_args()
    if len(stix_args.file) > 1 and stix_args.single_output and stix_args.output_dir is None:
        stix_args.output_dir = Path(__file__).parents[1] / 'tmp'

    results = _misp_to_stix(stix_args) if stix_args.export else _stix_to_misp(stix_args)
    if isinstance(results, list):
        files = '\n - '.join(str(result) for result in results)
        print(
            'Successfully processed your '
            f"{'files' if len(results) > 1 else 'file'}. Results available in:"
            f"\n - {files}"
        )
    else:
        print(
            'Successfully processed your '
            f"{'files' if len(stix_args.file) > 1 else 'file'}. "
            f"Results available in {results}"
        )
