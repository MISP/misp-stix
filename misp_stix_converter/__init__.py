__version__ = '2.4.194'

import argparse
from .misp_stix_mapping import Mapping # noqa
from .misp2stix import MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser # noqa
from .misp2stix import MISPtoSTIX1Mapping # noqa
from .misp2stix import MISPtoSTIX20Parser, MISPtoSTIX21Parser # noqa
from .misp2stix import MISPtoSTIX20Mapping, MISPtoSTIX21Mapping # noqa
from .misp2stix import stix1_attributes_framing, stix1_framing # noqa
from .misp2stix import stix20_framing, stix21_framing # noqa
# Helpers
from .misp_stix_converter import ( # noqa
    _from_misp, misp_attribute_collection_to_stix1, misp_collection_to_stix2,
    misp_event_collection_to_stix1, misp_to_stix1, misp_to_stix2,
    stix_1_to_misp, stix_2_to_misp)
# STIX 1 special helpers
from .misp_stix_converter import ( # noqa
    _get_campaigns, _get_courses_of_action, _get_events, _get_indicators,
    _get_observables, _get_threat_actors, _get_ttps, _from_misp)
# STIX 1 footers
from .misp_stix_converter import ( # noqa
    _get_campaigns_footer, _get_courses_of_action_footer, _get_indicators_footer,
    _get_observables_footer, _get_threat_actors_footer, _get_ttps_footer)
# STIX 1 headers
from .misp_stix_converter import ( # noqa
    _get_campaigns_header, _get_courses_of_action_header, _get_indicators_header,
    _get_observables_header, _get_threat_actors_header, _get_ttps_header)
# Command line methods
from .misp_stix_converter import _misp_to_stix, _stix_to_misp # noqa
from .stix2misp import ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser # noqa
from .stix2misp import ExternalSTIX2toMISPMapping, InternalSTIX2toMISPMapping # noqa
from .stix2misp import STIX2PatternParser # noqa
from .stix2misp import MISP_org_uuid # noqa
from pathlib import Path


def _handle_return_message(traceback):
    if isinstance(traceback, dict):
        messages = []
        for key, values in traceback.items():
            messages.append(f'- {key}')
            for value in values:
                messages.append(f'  - {value}')
        return '\n '.join(messages)
    return '\n - '.join(traceback)


def main():
    parser = argparse.ArgumentParser(description='Convert MISP <-> STIX')
    parser.add_argument(
        '--debug', action='store_true', help='Show errors and warnings'
    )

    # SUBPARSERS TO SEPARATE THE 2 MAIN FEATURES
    subparsers = parser.add_subparsers(
        title='Main feature', dest='feature', required=True
    )

    # EXPORT SUBPARSER
    export_parser = subparsers.add_parser(
        'export', help='Export MISP to STIX - try '
                       '`misp_stix_converter export -h` for more help.'
    )
    export_parser.add_argument(
        '-f', '--file', nargs='+', type=Path, required=True,
        help='Path to the file(s) to convert.'
    )
    export_parser.add_argument(
        '-v', '--version', choices=['1.1.1', '1.2', '2.0', '2.1'],
        required=True, help='STIX specific version.'
    )
    export_parser.add_argument(
        '-s', '--single_output', action='store_true',
        help='Produce only one result file (in case of multiple input file).'
    )
    export_parser.add_argument(
        '-m', '--in_memory', action='store_true',
        help='Store result in memory (in case of multiple result files) '
             'instead of storing it in tmp files.'
    )
    export_parser.add_argument(
        '--output_dir', type=Path,
        help='Output path - used in the case of multiple input files when the '
             '`single_output` argument is not used.'
    )
    export_parser.add_argument(
        '-o', '--output_name', type=Path,
        help='Output file name - used in the case of a single input file or '
             'when the `single_output` argument is used.'
    )
    # STIX 1 EXPORT SPECIFIC ARGUMENTS
    stix1_parser = export_parser.add_argument_group('STIX 1 specific arguments')
    stix1_parser.add_argument(
        '--level', default='event', choices=['attribute', 'event'],
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
    export_parser.set_defaults(func=_misp_to_stix)

    # IMPORT SUBPARSER
    import_parser = subparsers.add_parser(
        'import', help='Import STIX to MISP - try '
                       '`misp_stix_converter import -h` for more help.'
    )
    import_parser.add_argument(
        '-f', '--file', nargs='+', type=Path, required=True,
        help='Path to the file(s) to convert.'
    )
    import_parser.add_argument(
        '-v', '--version', choices=['1', '2'],
        required=True, help='STIX major version.'
    )
    import_parser.add_argument(
        '-s', '--single_output', action='store_true',
        help='Produce only one MISP event per STIX file'
             '(in case of multiple Report, Grouping or Incident objects).'
    )
    import_parser.add_argument(
        '-o', '--output_name', type=Path,
        help='Output file name - used in the case of a single input file or '
             'when the `single_output` argument is used.'
    )
    import_parser.add_argument(
        '--output_dir', type=Path,
        help='Output path - used in the case of multiple input files when the '
             '`single_output` argument is not used.'
    )
    import_parser.add_argument(
        '-d', '--distribution', type=int, default=0,
        help='Distribution level for the imported MISP content.'
    )
    import_parser.add_argument(
        '-sg', '--sharing_group', type=int, default=None,
        help='Sharing group ID when distribution is 4.'
    )
    import_parser.add_argument(
        '--galaxies_as_tags', action='store_true',
        help='Import MISP Galaxies as tag names instead of the standard Galaxy format.'
    )
    import_parser.add_argument(
        '--org_uuid', default=MISP_org_uuid,
        help='Organisation UUID to use when creating custom Galaxy clusters.'
    )
    import_parser.add_argument(
        '-cd', '--cluster_distribution', type=int, default=0,
        help='Galaxy Clusters distribution level in case of External STIX 2 content.'
    )
    import_parser.add_argument(
        '-cg', '--cluster_sharing_group', type=int, default=None,
        help='Galaxy Clusters sharing group ID in case of External STIX 2 content.'
    )
    import_parser.set_defaults(func=_stix_to_misp)

    stix_args = parser.parse_args()
    if len(stix_args.file) > 1 and stix_args.single_output and stix_args.output_dir is None:
        stix_args.output_dir = Path(__file__).parents[1] / 'tmp'
    feature = 'MISP to STIX' if stix_args.feature == 'export' else 'STIX to MISP'
    try:
        traceback = stix_args.func(stix_args)
        for field in ('errors', 'warnings'):
            if field in traceback:
                messages = _handle_return_message(traceback[field])
                print(f'{field.capitalize()} encountered during the '
                        f'{feature} conversion process:\n {messages}')
        if 'fails' in traceback:
            fails = _handle_return_message(traceback['fails'])
            print('Failed parsing the following - and the related error '
                    f'message:\n {fails}')
        if 'results' in traceback:
            results = traceback['results']
            if isinstance(results, list):
                files = '\n - '.join(str(result) for result in results)
                print(
                    'Successfully processed your '
                    f"{'files' if len(results) > 1 else 'file'}. Results "
                    f"available in:\n - {files}"
                )
            else:
                print(
                    'Successfully processed your '
                    f"{'files' if len(stix_args.file) > 1 else 'file'}. "
                    f"Results available in {results}"
                )
        else:
            print(f'No result from the {feature} conversion.')
    except Exception as exception:
        print(f'Breaking exception encountered during the {feature} conversion '
              f'process: {exception.__str__()}')
