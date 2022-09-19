# MISP-STIX - Python library to handle the conversion between MISP standard and STIX

<img src="https://raw.githubusercontent.com/MISP/misp-stix/main/documentation/logos/misp-stix.png" width="125" height="125">

[![Python version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/release/python-370/)
[![MISP-STIX version](https://badge.fury.io/gh/MISP%2Fmisp-stix.svg)](https://badge.fury.io/gh/MISP%2Fmisp-stix)
[![Github Actions](https://github.com/MISP/misp-stix/workflows/misp-stix/badge.svg)](https://github.com/MISP/misp-stix/actions?query=workflow%3Amisp-stix)
[![License](https://img.shields.io/github/license/MISP/misp-stix.svg)](#License)

MISP-STIX-converter is a Python library (>=3.7) to handle all the conversions between the [MISP standard format](https://www.misp-standard.org/) and STIX formats.

The package is available as [misp-stix](https://pypi.org/project/misp-stix/) in PyPI.

## Features

- MISP standard format conversion to STIX 1.x (1.1.1 and 1.2)
- MISP standard format conversion to STIX 2.x (2.0 and 2.1)
- Maps [MISP Objects](https://github.com/MISP/misp-objects) and [MISP galaxies](https://github.com/misp/misp-galaxy) with [respective semantically similar objects](https://github.com/MISP/misp-stix/tree/main/documentation)
- STIX to MISP standard format
- Provides an extendable library for mapping and facilitate extension

This library is used by the [MISP core software](https://github.com/MISP/MISP) to perform STIX conversion and serving as a useful tool for anyone looking for a clean way of converting between the MISP standard format and various STIX versions (1.1.1, 1.2, 2.0, 2.1).

A complete [documentation is available](/documentation/) including the mappings between the different formats.

## Install from pip

**It is strongly recommended to use a virtual environment**

If you want to know more about virtual environments, [python has you covered](https://docs.python.org/3/tutorial/venv.html)

From the current repository:
```
pip3 install misp-stix
```

Package details at PyPI: [misp-stix](https://pypi.org/project/misp-stix/)

## Install the latest version from the repository for development purposes

**Note**: poetry is required; e.g., "pip3 install poetry"

```
git clone https://github.com/MISP/misp-stix.git && cd misp-stix
git submodule update --init
poetry install
```

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
misp_stix_converter --version 2.1 -f tests/test_events_collection_1.json
```

#### Parameters

- `--version`: STIX version
- `--file`: Input file(s)

Parameters specific to the case of multiple input file(s):
- `--single_output`: In case of multiple input files, save the results in on single file
- `--tmp_files`: Store temporary results in files before gathering the whole conversion result, instead of keeping it on memory

Parameters specific to STIX 1 export:
- `--feature`: MISP data structure level (attribute or event)
- `--namespace`: Namespace to be used in the STIX 1 header
- `--org`: Organisation name to be used in the STIX 1 header

### In Python scripts

Given a MISP Event (with its metadata fields, attributes, objects, galaxies and tags), declared in an `event` variable in JSON format, you can get the result of a conversion into one of the supported STIX versions:

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
# response = 1 if everything went well
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
from misp_stix_converter import misp_to_stix2_0, misp_to_stix2_1

response_20 = misp_to_stix2_0(filename)
response_21 = misp_to_stix2_1(filename)
# Again response_20 & response_21 should be 1 if everything went well
```
The resulting STIX2 Bundle is the available in a `filename.out` file

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
from misp_stix_converter import misp_event_collection_to_stix1, misp_event_collection_to_stix2_0, misp_event_collection_to_stix2_1

input_filenames = [filename for filename in Path(_PATH_TO_YOUR_MISP_FILES_).glob('*.json')]

stix1_response = misp_event_collection_to_stix1(
    output_filename, # path to the file where the results are going to be written
    'xml', # STIX1 return format (XML or JSON)
    '1.1.1', # STIX1 version (1.1.1 or 1.2)
    *input_filenames
)

stix20_response = misp_event_collection_to_stix2_0(
    output_filename, # path to the file where the results are going to be written
    *input_filenames
)

stix21_response = misp_event_collection_to_stix2_1(
    output_filename, # path to the file where the results are going to be written
    *input_filenames
)
```
Again, all the response variables should be `1` and the resulting STIX1 Package and STIX 2.0 & 2.1 Bundles are available in the specific output file names.

### Samples and examples

Various examples are provided and used by the different tests scripts in the [tests](tests/) directory.
Those example files are showing the results of MISP format exported in the various supported STIX formats.

## MISP <--> STIX Mapping

A specific documentation concerning the mapping between MISP and the various supported STIX versions is also provided in the [documentation](documentation/) directory.
You can find there all the different cases illustrated with examples.

# License

misp-stix is released under a BSD 2-Clause "Simplified" License allow easy reuse with other libraries.

~~~
Copyright 2019-2022 Christian Studer
Copyright 2019-2022 CIRCL - Computer Incident Response Center Luxembourg c/o "security made in Lëtzebuerg" (SMILE) g.i.e.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
~~~
