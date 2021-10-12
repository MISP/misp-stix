**IMPORTANT NOTE**: This library requires **at least** python 3.6

# MISP-STIX-Converter - Python library to handle the conversion between MISP and STIX

MISP-STIX-Converter is a Python library to handle all the interactions between the [MISP standard format](https://www.misp-standard.org/) and STIX formats.

MISP-STIX-Converter allows you to convert:

- MISP -> STIX1 (1.1.1 & 1.2)
- MISP -> STIX2 (2.0 & 2.1)
- (WiP) STIX -> MISP

This library is used by the MISP core software to perform STIX conversion and serving as a useful tool for anyone looking for a clean way of converting between the MISP standard format and various STIX versions (1.1.1, 1.2, 2.0, 2.1).

A complete [documentation is available](/documentation/) including the mappings between the different formats.

## Install from pip

**It is strongly recommended to use a virtual environment**

If you want to know more about virtual environements, [python has you covered](https://docs.python.org/3/tutorial/venv.html)

From the current repository:
```
pip3 install .
```

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
poetry run nosetests-3.4 --with-coverage --cover-package=tests --cover-tests tests/test_stix1_export.py
```

Tests for MISP format export as STIX 2.0:
```bash
poetry run nosetests-3.4 --with-coverage --cover-package=tests --cover-tests tests/test_stix20_export.py
```

Tests for MISP format export as STIX 2.1:
```bash
poetry run nosetests-3.4 --with-coverage --cover-package=tests --cover-tests tests/test_stix21_export.py
```

## Samples and examples

Various examples are provided and used by the different tests scripts in the [tests](tests/) directory.
Those example files are showing the results of MISP format exported in the various supported STIX formats.

### Usage examples

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

## MISP <--> STIX Mapping

A specific documentation concerning the mapping between MISP and the various supported STIX versions is also provided in the [documentation](documentation/) directory.
You can find there all the different cases illustrated with examples.
