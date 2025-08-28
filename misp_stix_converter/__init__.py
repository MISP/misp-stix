__version__ = '2025.8.28'

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
    _get_stix2_parser, _is_stix1_from_misp, _is_stix2_from_misp,
    misp_attribute_collection_to_stix1, misp_collection_to_stix2,
    misp_event_collection_to_stix1, misp_to_stix1, misp_to_stix2,
    stix_1_to_misp, stix_2_to_misp, stix2_to_misp_instance)
# STIX 1 special helpers
from .misp_stix_converter import ( # noqa
    _get_campaigns, _get_courses_of_action, _get_events, _get_indicators,
    _get_observables, _get_threat_actors, _get_ttps)
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
from .stix2misp import ExternalSTIX2Mapping  # noqa
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
        '-v', '--version', action='version',
        version=f'{parser.prog} {__version__}'
    )
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
        '-s', '--single-output', action='store_true',
        help='Produce only one result file (in case of multiple input file).'
    )
    export_parser.add_argument(
        '-m', '--in-memory', action='store_true',
        help='Store result in memory (in case of multiple result files) '
             'instead of storing it in tmp files.'
    )
    export_parser.add_argument(
        '--output-dir', type=Path,
        help='Output path - used in the case of multiple input files when the '
             '`single_output` argument is not used.'
    )
    export_parser.add_argument(
        '-o', '--output-name', type=Path,
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
        'import', help='Import STIX to MISP - try `misp_stix_converter import -h` for more help.'
    )
    import_parser.add_argument(
        '-f', '--file', nargs='+', type=Path, required=True,
        help='Path to the file(s) to convert.'
    )
    import_parser.add_argument(
        '-v', '--version', choices=['1', '2'], default='2',
        help='STIX major version - default is 2'
    )
    import_parser.add_argument(
        '-s', '--single-event', action='store_true',
        help='Produce only one MISP event per STIX file'
             '(in case of multiple Report, Grouping or Incident objects).'
    )
    import_parser.add_argument(
        '-o', '--output-name', type=Path,
        help='Output file name - used in the case of a single input file or '
             'when the `single_event` argument is used.'
    )
    import_parser.add_argument(
        '--output-dir', type=Path,
        help='Output path - used in the case of multiple input files when the '
             '`single_event` argument is not used.'
    )
    import_parser.add_argument(
        '-d', '--distribution', type=int, default=0, choices=[0, 1, 2, 3, 4],
        help='''
            Distribution level for the imported MISP content (default is 0)
              - 0: Your organisation only
              - 1: This community only
              - 2: Connected communities
              - 3: All communities
              - 4: Sharing Group
            '''
    )
    import_parser.add_argument(
        '-sg', '--sharing-group', type=int, default=None,
        help='Sharing group ID when distribution is 4.'
    )
    import_parser.add_argument(
        '--galaxies-as-tags', action='store_true',
        help='Import MISP Galaxies as tag names instead of the standard Galaxy format.'
    )
    import_parser.add_argument(
        '--no-force-contextual-data', action='store_true',
        help='Do not force the creation of custom Galaxy clusters in some specific cases when STIX objects could be converted either as clusters or MISP objects for instance.'
    )
    import_parser.add_argument(
        '--org-uuid', help='Organisation UUID to use when creating custom Galaxy clusters.'
    )
    import_parser.add_argument(
        '-cd', '--cluster-distribution', type=int, default=0, choices=[0, 1, 2, 3, 4],
        help='''
            Galaxy Clusters distribution level
            in case of External STIX 2 content (default id 0)
              - 0: Your organisation only
              - 1: This community only
              - 2: Connected communities
              - 3: All communities
              - 4: Sharing Group
        '''
    )
    import_parser.add_argument(
        '-csg', '--cluster-sharing-group', type=int, default=None,
        help='Galaxy Clusters sharing group ID in case of External STIX 2 content.'
    )
    import_parser.add_argument(
        '-t', '--title', type=str, default=None,
        help='Title used to set the MISP Event `info` field.'
    )
    import_parser.add_argument(
        '-p', '--producer',
        help=(
            'Producer of the imported content - Please make sure you use a '
            'name from the list of existing producer Galaxy Clusters.'
        )
    )
    import_parser.add_argument(
        '-c', '--config', type=Path,
        help='Config file containing the URL and the authentication key to connect to your MISP.'
    )
    import_parser.add_argument(
        '-u', '--url', type=str, help='URL to connect to your MISP instance.'
    )
    import_parser.add_argument(
        '-a', '--api-key', type=str,
        help='Authentication key to connect to your MISP instance.'
    )
    import_parser.add_argument(
        '--skip-ssl', action='store_true',
        help='Skip SSL certificate checking when connecting to your MISP instance.'
    )
    import_parser.set_defaults(func=_stix_to_misp)

    stix_args = parser.parse_args()
    single = (
        stix_args.single_output if stix_args.feature == 'export'
        else stix_args.single_event
    )
    if len(stix_args.file) > 1 and single and stix_args.output_dir is None:
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
            print(
                'Failed parsing the following - '
                f'and the related error message:\n {fails}'
            )
        if 'pymisp_errors' in traceback:
            for event_uuid, message in traceback['pymisp_errors'].items():
                print(f'Error adding MISP Event {event_uuid}: {message}')
        if 'results' in traceback:
            results = traceback['results']
            if isinstance(results, list):
                files = '\n - '.join(str(result) for result in results)
                print(
                    'Successfully processed your '
                    f"{'files' if len(stix_args.file) > 1 else 'file'}.\n"
                    f'Results written in:\n - {files}'
                )
            else:
                print(
                    'Successfully processed your '
                    f"{'files' if len(stix_args.file) > 1 else 'file'}.\n"
                    f"Results written in {results}"
                )
        elif 'event_ids' in traceback:
            event_ids = traceback['event_ids']
            if isinstance(event_ids, list):
                links = '\n - '.join(
                    f'{stix_args.url}/events/view/{event_id}'
                    for event_id in event_ids
                )
                print(
                    'Successfully processed your '
                    f"{'files' if len(stix_args.file) > 1 else 'file'}.\n"
                    f'Results available in MISP:\n - {links}'
                )
            else:
                print(
                    'Successfully processed your '
                    f"{'files' if len(stix_args.file) > 1 else 'file'}.\n"
                    'Results available in MISP: '
                    f'{stix_args.file}/events/view/{event_ids}'
                )
        else:
            print(f'No result from the {feature} conversion.')
    except Exception as exception:
        print(f'Breaking exception encountered during the {feature} conversion '
              f'process: {exception.__str__()}')
