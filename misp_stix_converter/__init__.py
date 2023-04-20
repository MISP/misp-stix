__version__ = '2.4.170'

import argparse
from .misp_stix_mapping import Mapping
from .misp2stix import *
# Helpers
from .misp_stix_converter import (
    _from_misp, misp_attribute_collection_to_stix1, misp_collection_to_stix2_0,
    misp_collection_to_stix2_1, misp_event_collection_to_stix1, misp_to_stix1,
    misp_to_stix2_0, misp_to_stix2_1, stix_1_to_misp, stix_2_to_misp)
# STIX 1 special halpers
from .misp_stix_converter import (
    _get_campaigns, _get_courses_of_action, _get_events, _get_indicators,
    _get_observables, _get_threat_actors, _get_ttps)
# STIX 1 footers
from .misp_stix_converter import (
    _get_campaigns_footer, _get_courses_of_action_footer, _get_indicators_footer,
    _get_observables_footer, _get_threat_actors_footer, _get_ttps_footer)
# STIX 1 headers
from .misp_stix_converter import (
    _get_campaigns_header, _get_courses_of_action_header, _get_indicators_header,
    _get_observables_header, _get_threat_actors_header, _get_ttps_header)
# Command line methods
from .misp_stix_converter import _misp_to_stix, _stix_to_misp
from .stix2misp import *
from pathlib import Path


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
