# MISP-STIX - Python library to handle the conversion between MISP standard and STIX

<img src="https://raw.githubusercontent.com/MISP/misp-stix/main/documentation/logos/misp-stix.png" width="125" height="125">

[![Python version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/release/python-370/)
[![MISP-STIX version](https://badge.fury.io/gh/MISP%2Fmisp-stix.svg)](https://badge.fury.io/gh/MISP%2Fmisp-stix)
[![Github Actions](https://github.com/MISP/misp-stix/workflows/misp-stix/badge.svg)](https://github.com/MISP/misp-stix/actions?query=workflow%3Amisp-stix)
[![License](https://img.shields.io/github/license/MISP/misp-stix.svg)](#License)

MISP-STIX-converter is a Python library (>=3.8) to handle all the conversions between the [MISP standard format](https://www.misp-standard.org/) and STIX formats.

The package is available as [misp-stix](https://pypi.org/project/misp-stix/) in PyPI.

## Features

- MISP standard format conversion to STIX 1.x (1.1.1 and 1.2)
- MISP standard format conversion to STIX 2.x (2.0 and 2.1)
- Maps [MISP Objects](https://github.com/MISP/misp-objects) and [MISP galaxies](https://github.com/misp/misp-galaxy) with [respective semantically similar objects](https://github.com/MISP/misp-stix/tree/main/documentation)
- STIX to MISP standard format
- Provides an extendable library for mapping and facilitate extension

This library is used by the [MISP core software](https://github.com/MISP/MISP) to perform STIX conversion and serving as a useful tool for anyone looking for a clean way of converting between the MISP standard format and various STIX versions (1.1.1, 1.2, 2.0, 2.1).

A complete [documentation is available](./documentation/) including the mappings between the different formats.

## Install from pip

**It is strongly recommended to use a virtual environment**

If you want to know more about virtual environments, [python has you covered](https://docs.python.org/3/tutorial/venv.html)

From the current repository:
```
pip3 install misp-stix
```

Package details at PyPI: [misp-stix](https://pypi.org/project/misp-stix/)

## Install the latest version from the repository for development purposes

**Note**: poetry is required; e.g., `pip3 install poetry`

```
git clone https://github.com/MISP/misp-stix.git && cd misp-stix
git submodule update --init
poetry install
```

If you already have poetry face any issue with it while installing or updating misp-stix with it, you can try `pip3 install -U poetry` to make sure you have a version >= 1.2

### Running the tests

Tests for MISP format export as STIX 1.1.1 & 1.2:
```bash
poetry run pytest tests/test_stix1_export.py
```

Tests for MISP format export as STIX 2.0:
```bash
poetry run pytest tests/test_stix20_export.py
```

Tests for MISP format export as STIX 2.1:
```bash
poetry run pytest tests/test_stix21_export.py
```

## Usage

### Command-line Usage

```
misp_stix_converter export --version 2.1 -f tests/test_events_collection_1.json
```

#### Parameters

```bash
usage: misp_stix_converter [-h] [--debug] {export,import} ...

Convert MISP <-> STIX

options:
  -h, --help       show this help message and exit
  --debug          Show errors and warnings

Main feature:
  {export,import}
    export         Export MISP to STIX - try `misp_stix_converter export -h` for more help.
    import         Import STIX to MISP - try `misp_stix_converter import -h` for more help.
```

##### Export parameters

```bash
usage: misp_stix_converter export [-h] -f FILE [FILE ...] -v {1.1.1,1.2,2.0,2.1} [-s] [-m] [--output_dir OUTPUT_DIR] [-o OUTPUT_NAME] [--level {attribute,event}] [--format {json,xml}] [-n NAMESPACE] [-org ORG]

options:
  -h, --help            show this help message and exit
  -f FILE [FILE ...], --file FILE [FILE ...]
                        Path to the file(s) to convert.
  -v {1.1.1,1.2,2.0,2.1}, --version {1.1.1,1.2,2.0,2.1}
                        STIX specific version.
  -s, --single_output   Produce only one result file (in case of multiple input file).
  -m, --in_memory       Store result in memory (in case of multiple result files) instead of storing it in tmp files.
  --output_dir OUTPUT_DIR
                        Output path - used in the case of multiple input files when the `single_output` argument is not used.
  -o OUTPUT_NAME, --output_name OUTPUT_NAME
                        Output file name - used in the case of a single input file or when the `single_output` argument is used.

STIX 1 specific arguments:
  --level {attribute,event}
                        MISP data structure level.
  --format {json,xml}   STIX 1 format.
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace to be used in the STIX 1 header.
  -org ORG              Organisation name to be used in the STIX 1 header.
```

##### Import parameters

```bash
usage: misp_stix_converter import [-h] -f FILE [FILE ...] -v {1,2} [-s] [-o OUTPUT_NAME] [--output_dir OUTPUT_DIR] [-d DISTRIBUTION] [-sg SHARING_GROUP] [--galaxies_as_tags]

options:
  -h, --help            show this help message and exit
  -f FILE [FILE ...], --file FILE [FILE ...]
                        Path to the file(s) to convert.
  -v {1,2}, --version {1,2}
                        STIX major version.
  -s, --single_output   Produce only one MISP event per STIX file(in case of multiple Report, Grouping or Incident objects).
  -o OUTPUT_NAME, --output_name OUTPUT_NAME
                        Output file name - used in the case of a single input file or when the `single_output` argument is used.
  --output_dir OUTPUT_DIR
                        Output path - used in the case of multiple input files when the `single_output` argument is not used.
  -d DISTRIBUTION, --distribution DISTRIBUTION
                        Distribution level for the imported MIPS content.
  -sg SHARING_GROUP, --sharing_group SHARING_GROUP
                        Sharing group ID when distribution is 4.
  --galaxies_as_tags    Import MISP Galaxies as tag names instead of the standard Galaxy format.
```

### In Python scripts

Given a MISP Event (with its metadata fields, attributes, objects, galaxies and tags), declared in an `event` variable in Python dict format, you can get the result of a conversion into one of the supported STIX versions:

- Convert a MISP Event in STIX1:

```python
from misp_stix_converter import MISPtoSTIX1EventsParser

parser = MISPtoSTIX1EventsParser(
    'MISP-Project', # Example of Org name
    '1.1.1' # STIX1 version (1.1.1 or 1.2)
)
parser.parse_misp_event(event)

stix_package = parser.stix_package
```

- Convert a MISP Event in STIX1 using directly its file name:

```python
from misp_stix_converter import misp_to_stix1

response = misp_to_stix1(
    filename, # file name of the file containing a MISP Event
    'xml', # return format (XML or JSON)
    '1.1.1' # STIX1 version (1.1.1 or 1.2)
)
# if everything went well, response is a dictionary where `success` = 1
```
The resulting STIX1 Package is then available in a `filename.out` file

- Convert a MISP Event in STIX2:

```python
# for STIX 2.0
from misp_stix_converter import MISPtoSTIX20Parser
# for STIX 2.1
from misp_stix_converter import MISPtoSTIX21Parser

parser20 = MISPtoSTIX20Parser()
parser20.parse_misp_event(event)

parser21 = MISPtoSTIX21Parser()
parser21.parse_misp_event(event)

# To get the list of parsed STIX objects
stix_20_objects = parser20.stix_objects
stix_21_objects = parser21.stix_objects

# To get the list of parser STIX objects within a STIX 2.0 or 2.1 Bundle
bundle20 = parser20.bundle
bundle21 = parser21.bundle
```

- Convert a MISP Event in STIX2 using directly its file name:

```python
from misp_stix_converter import misp_to_stix2

response_20 = misp_to_stix2(filename, version='2.0')
response_21 = misp_to_stix2(filename, version='2.1')
# Again response_20 & response_21 have a `success` field equal to 1 if everything went well
```
The resulting STIX2 Bundle is the available in a `filename.out` file, or you can define the output name with the `output_name` argument.

If you get some MISP collection of data, it is also possible to convert it straight into some STIX format:

```python
from misp_stix_converter import MISPtoSTIX1EventsParser, MISPtoSTIX20Parser, MISPtoSTIX21Parser

filename = _PATH_TO_YOUR_FILE_CONTAINING_MISP_FORMAT_

parser1 = MISPtoSTIX1EventsParser('MISP', '1.1.1')
parser1.parse_json_content(filename)
stix_package = parser1.stix_package

parser20 = MISPtoSTIX20Parser()
parser20.parse_json_content(filename)
stix_20_objects = parser20.stix_objects
bundle20 = parser20.bundle

parser21 = MISPtoSTIX21Parser()
parser21.parse_json_content(filename)
stix_21_objects = parser21.stix_objects
bundle21 = parser21.bundle
```

But in order to parse multiple data collections, you can also use the following helpers:

```python
from misp_stix_converter import misp_event_collection_to_stix1, misp_event_collection_to_stix2

input_filenames = [filename for filename in Path(_PATH_TO_YOUR_MISP_FILES_).glob('*.json')]

stix1_response = misp_event_collection_to_stix1(
    *input_filenames,
    output_name=output_filename, # path to the file where the results are going to be written
    return_format='xml', # STIX1 return format (XML or JSON)
    version='1.1.1' # STIX1 version (1.1.1 or 1.2)
)

stix20_response = misp_event_collection_to_stix2(
    *input_filenames,
    version='2.0' # STIX 2 version
)

stix21_response = misp_event_collection_to_stix2_1(
    *input_filenames,
    version='2.1',
    single_output=True, # For a single resulting file
    output_name=output_file_name, # path to the file where the results are going to be written
    in_memory=True # To keep results in memory before writing the full converted content at the end in the result file
)
```
Again, all the responses should have a `success` field equal to 1 and the resulting STIX1 Package and STIX 2.0 & 2.1 Bundles are available in the specific output file names.

### Samples and examples

Various examples are provided and used by the different tests scripts in the [tests](tests/) directory.
Those example files are showing the results of MISP format exported in the various supported STIX formats.

## MISP <--> STIX Mapping

A specific documentation concerning the mapping between MISP and the various supported STIX versions is also provided in the [documentation](documentation/) directory.
You can find there all the different cases illustrated with examples.

# License

misp-stix is released under a BSD 2-Clause "Simplified" License allow easy reuse with other libraries.

~~~
Copyright 2019-2023 Christian Studer
Copyright 2019-2023 CIRCL - Computer Incident Response Center Luxembourg c/o "security made in Lëtzebuerg" (SMILE) g.i.e.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
~~~
