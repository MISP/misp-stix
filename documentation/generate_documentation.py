# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
from pathlib import Path


class DocumentationGenerator():
    def __init__(self):
        current_path = Path(__file__).parent.resolve()
        # content
        self._introduction_filename = current_path / 'content/introduction.md'
        self._misp2stix_intro_filename = current_path / 'content/misp_to_stix_intro.md'
        self._misp_to_stix1_filename = current_path / 'content/misp_to_stix1.md'
        self._misp_to_stix20_filename = current_path / 'content/misp_to_stix20.md'
        self._misp_to_stix21_filename = current_path / 'content/misp_to_stix21.md'
        self._attributes_to_stix1_content = current_path / 'content/attributes_to_stix1_details.md'
        self._attributes_to_stix20_content = current_path / 'content/attributes_to_stix20_details.md'
        self._attributes_to_stix21_content = current_path / 'content/attributes_to_stix21_details.md'
        self._objects_to_stix1_content = current_path / 'content/objects_to_stix1_details.md'
        self._objects_to_stix20_content = current_path / 'content/objects_to_stix20_details.md'
        self._objects_to_stix21_content = current_path / 'content/objects_to_stix21_details.md'
        self._galaxies_to_stix1_content = current_path / 'content/galaxies_to_stix1_details.md'
        self._galaxies_to_stix20_content = current_path / 'content/galaxies_to_stix20_details.md'
        self._galaxies_to_stix21_content = current_path / 'content/galaxies_to_stix21_details.md'
        # mapping
        self._misp_attributes_to_stix1_mapping = current_path / 'mapping/misp_attributes_to_stix1.json'
        self._misp_attributes_to_stix20_mapping = current_path / 'mapping/misp_attributes_to_stix20.json'
        self._misp_attributes_to_stix20_summary = current_path / 'mapping/misp_attributes_to_stix20_summary.json'
        self._misp_attributes_to_stix21_mapping = current_path / 'mapping/misp_attributes_to_stix21.json'
        self._misp_attributes_to_stix21_summary = current_path / 'mapping/misp_attributes_to_stix21_summary.json'
        self._misp_custom_attributes_to_stix1_mapping = current_path / 'mapping/misp_custom_attributes_to_stix1.json'
        self._misp_custom_attributes_to_stix20_mapping = current_path / 'mapping/misp_custom_attributes_to_stix20.json'
        self._misp_custom_attributes_to_stix21_mapping = current_path / 'mapping/misp_custom_attributes_to_stix21.json'
        self._misp_custom_objects_to_stix1_mapping = current_path / 'mapping/misp_custom_objects_to_stix1.json'
        self._misp_custom_objects_to_stix20_mapping = current_path / 'mapping/misp_custom_objects_to_stix20.json'
        self._misp_custom_objects_to_stix21_mapping = current_path / 'mapping/misp_custom_objects_to_stix21.json'
        self._misp_objects_to_stix1_mapping = current_path / 'mapping/misp_objects_to_stix1.json'
        self._misp_objects_to_stix20_mapping = current_path / 'mapping/misp_objects_to_stix20.json'
        self._misp_objects_to_stix20_summary = current_path / 'mapping/misp_objects_to_stix20_summary.json'
        self._misp_objects_to_stix21_mapping = current_path / 'mapping/misp_objects_to_stix21.json'
        self._misp_objects_to_stix21_summary = current_path / 'mapping/misp_objects_to_stix21_summary.json'
        self._misp_galaxies_to_stix1_mapping = current_path / 'mapping/misp_galaxies_to_stix1.json'
        self._misp_galaxies_to_stix20_mapping = current_path / 'mapping/misp_galaxies_to_stix20.json'
        self._misp_galaxies_to_stix21_mapping = current_path / 'mapping/misp_galaxies_to_stix21.json'
        # documentation results
        self._misp_attributes_to_stix1 = current_path / 'misp_attributes_to_stix1.md'
        self._misp_attributes_to_stix20 = current_path / 'misp_attributes_to_stix20.md'
        self._misp_attributes_to_stix21 = current_path / 'misp_attributes_to_stix21.md'
        self._misp_objects_to_stix1 = current_path / 'misp_objects_to_stix1.md'
        self._misp_objects_to_stix20 = current_path / 'misp_objects_to_stix20.md'
        self._misp_objects_to_stix21 = current_path / 'misp_objects_to_stix21.md'
        self._misp_galaxies_to_stix1 = current_path / 'misp_galaxies_to_stix1.md'
        self._misp_galaxies_to_stix20 = current_path / 'misp_galaxies_to_stix20.md'
        self._misp_galaxies_to_stix21 = current_path / 'misp_galaxies_to_stix21.md'
        self._output_filename = current_path / 'README.md'

    def generate_documentation(self):
        self._generate_introduction()
        self._generate_misp_to_stix_introduction()
        self._generate_misp_to_stix1_documentation()
        self._generate_misp_to_stix20_documentation()
        self._generate_misp_to_stix21_documentation()

    def write_documentation(self):
        with open(self._output_filename, 'wt', encoding='utf-8') as f:
            f.write('\n\n'.join(
                [
                    self._introduction,
                    self._misp_to_stix_introduction,
                    self._misp_to_stix1,
                    self._misp_to_stix20,
                    self._misp_to_stix21
                ]
            ))

    def _generate_introduction(self):
        with open(self._introduction_filename, 'rt', encoding='utf-8') as f:
            self._introduction = f.read()

    def _generate_misp_to_stix_introduction(self):
        with open(self._misp2stix_intro_filename, 'rt', encoding='utf-8') as f:
            self._misp_to_stix_introduction = f.read()

    def _generate_misp_to_stix1_documentation(self):
        with open(self._misp_to_stix1_filename, 'rt', encoding='utf-8') as f:
            self._misp_to_stix1 = f.read()
        # Attributes documentation
        with open(self._misp_attributes_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        args = ('stix1', 'xml')
        mapping = self._parse_mapping(mapping, *args)
        with open(self._misp_custom_attributes_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, *args)
        with open(self._attributes_to_stix1_content, 'rt', encoding='utf-8') as f:
            attributes_mapping = f.read().format(
                _attributes_to_stix1_mapping_=mapping,
                _custom_attributes_to_stix1_mapping_=custom_mapping
            )
        with open(self._misp_attributes_to_stix1, 'wt', encoding='utf-8') as f:
            f.write(attributes_mapping)
        # Objects documentation
        with open(self._misp_objects_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        mapping = self._parse_mapping(mapping, *args)
        with open(self._misp_custom_objects_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, *args)
        with open(self._objects_to_stix1_content, 'rt', encoding='utf-8') as f:
            objects_mapping = f.read().format(
                _objects_to_stix1_mapping_=mapping,
                _custom_objects_to_stix1_mapping_=custom_mapping
            )
        with open(self._misp_objects_to_stix1, 'wt', encoding='utf-8') as f:
            f.write(objects_mapping)
        # Galaxies documentation
        with open(self._misp_galaxies_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        mapping = self._parse_mapping(mapping, *args)
        with open(self._galaxies_to_stix1_content, 'rt', encoding='utf-8') as f:
            galaxies_mapping = f.read().format(_galaxies_to_stix1_mapping_=mapping)
        with open(self._misp_galaxies_to_stix1, 'wt', encoding='utf-8') as f:
            f.write(galaxies_mapping)

    def _generate_misp_to_stix20_documentation(self):
        # Attributes documentation
        with open(self._misp_attributes_to_stix20_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        with open(self._misp_attributes_to_stix20_summary, 'rt', encoding='utf-8') as f:
            attributes_summary = self._parse_summary(json.loads(f.read()))
        data_format = 'json'
        mapping = self._parse_mapping(mapping, 'stix2', data_format)
        with open(self._misp_custom_attributes_to_stix20_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, 'stix2_custom', data_format)
        with open(self._attributes_to_stix20_content, 'rt', encoding='utf-8') as f:
            attributes_mapping = f.read().format(
                _attributes_to_stix20_mapping_=mapping,
                _custom_attributes_to_stix20_mapping_=custom_mapping
            )
        with open(self._misp_attributes_to_stix20, 'wt', encoding='utf-8') as f:
            f.write(attributes_mapping)
        # Objects documentation
        with open(self._misp_objects_to_stix20_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        with open(self._misp_objects_to_stix20_summary, 'rt', encoding='utf-8') as f:
            objects_summary = self._parse_summary(json.loads(f.read()))
        mapping = self._parse_mapping(mapping, 'stix2', data_format)
        with open(self._misp_custom_objects_to_stix20_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, 'stix2_custom', data_format)
        with open(self._objects_to_stix20_content, 'rt', encoding='utf-8') as f:
            objects_mapping = f.read().format(
                _objects_to_stix20_mapping_=mapping,
                _custom_objects_to_stix20_mapping_=custom_mapping
            )
        with open(self._misp_objects_to_stix20, 'wt', encoding='utf-8') as f:
            f.write(objects_mapping)
        # Galaxies documentation
        with open(self._misp_galaxies_to_stix20_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        mapping = self._parse_mapping(mapping, 'stix2_custom', data_format)
        with open(self._galaxies_to_stix20_content, 'rt', encoding='utf-8') as f:
            galaxies_mapping = f.read().format(_galaxies_to_stix20_mapping_=mapping)
        with open(self._misp_galaxies_to_stix20, 'wt', encoding='utf-8') as f:
            f.write(galaxies_mapping)
        # Formatting the STIX 2.0 documentation summary
        with open(self._misp_to_stix20_filename, 'rt', encoding='utf-8') as f:
            self._misp_to_stix20 = f.read().format(
                _attributes_to_stix20_summary_=attributes_summary,
                _objects_to_stix20_summary_=objects_summary
            )
            print(self._misp_to_stix20)

    def _generate_misp_to_stix21_documentation(self):
        # Attributes documentation
        with open(self._misp_attributes_to_stix21_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        with open(self._misp_attributes_to_stix21_summary, 'rt', encoding='utf-8') as f:
            attributes_summary = self._parse_summary(json.loads(f.read()))
        data_format = 'json'
        mapping = self._parse_mapping(mapping, 'stix2', data_format)
        with open(self._misp_custom_attributes_to_stix21_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, 'stix2_custom', data_format)
        with open(self._attributes_to_stix21_content, 'rt', encoding='utf-8') as f:
            attributes_mapping = f.read().format(
                _attributes_to_stix21_mapping_=mapping,
                _custom_attributes_to_stix21_mapping_=custom_mapping
            )
        with open(self._misp_attributes_to_stix21, 'wt', encoding='utf-8') as f:
            f.write(attributes_mapping)
        # Objects documentation
        with open(self._misp_objects_to_stix21_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        with open(self._misp_objects_to_stix21_summary, 'rt', encoding='utf-8') as f:
            objects_summary = self._parse_summary(json.loads(f.read()))
        mapping = self._parse_mapping(mapping, 'stix2', data_format)
        with open(self._misp_custom_objects_to_stix21_mapping, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(custom_mapping, 'stix2_custom', data_format)
        with open(self._objects_to_stix21_content, 'rt', encoding='utf-8') as f:
            objects_mapping = f.read().format(
                _objects_to_stix21_mapping_=mapping,
                _custom_objects_to_stix21_mapping_=custom_mapping
            )
        with open(self._misp_objects_to_stix21, 'wt', encoding='utf-8') as f:
            f.write(objects_mapping)
        # Galaxies documentation
        with open(self._misp_galaxies_to_stix21_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        mapping = self._parse_mapping(mapping, 'stix2_custom', data_format)
        with open(self._galaxies_to_stix21_content, 'rt', encoding='utf-8') as f:
            galaxies_mapping = f.read().format(_galaxies_to_stix21_mapping_=mapping)
        with open(self._misp_galaxies_to_stix21, 'wt', encoding='utf-8') as f:
            f.write(galaxies_mapping)
        # Formatting the STIX 2.1 documentation summary
        with open(self._misp_to_stix21_filename, 'rt', encoding='utf-8') as f:
            self._misp_to_stix21 = f.read().format(
                _attributes_to_stix21_summary_=attributes_summary,
                _objects_to_stix21_summary_=objects_summary
            )

    def _parse_mapping(self, misp2stix_mapping, stix_type, data_format):
        table = []
        for attribute_type, mapping in misp2stix_mapping.items():
            table.append(
                getattr(self, f"_parse_{stix_type}_table_line")(
                    attribute_type,
                    mapping,
                    data_format
                )
            )
        return '\n'.join(table)

    @staticmethod
    def _parse_json_documentation(attribute, feature, n=4):
        blank = ' ' * n
        blob = (f'{blank}{line}' for line in json.dumps(attribute, indent=4).split('\n'))
        misp_blob = '\n'.join(blob)
        return f"{blank[:-2]}- {feature}\n{blank}```json\n{misp_blob}\n{blank}```"

    def _parse_stix1_table_line(self, attribute_type, mapping, format):
        misp_blob = self._parse_json_documentation(mapping['MISP'], 'MISP')
        stix_blob = f"  - STIX\n    ```{format}\n{mapping['STIX']}\n    ```"
        return f'- {attribute_type}\n{misp_blob}\n{stix_blob}\n'

    def _parse_stix2_table_line(self, attribute_type, mapping, format):
        misp_blob = self._parse_json_documentation(mapping['MISP'], 'MISP')
        stix_blob = '\n'.join(self._parse_json_documentation(stix_mapping, feature, n=6) for feature, stix_mapping in mapping['STIX'].items())
        return f'- {attribute_type}\n{misp_blob}\n  - STIX\n{stix_blob}\n'

    def _parse_stix2_custom_table_line(self, attribute_type, mapping, format):
        misp_blob = self._parse_json_documentation(mapping['MISP'], 'MISP')
        stix_blob = self._parse_json_documentation(mapping['STIX'], 'STIX')
        return f'- {attribute_type}\n{misp_blob}\n{stix_blob}\n'

    @staticmethod
    def _parse_summary(mapping):
        summary = []
        for attribute_type, feature in mapping.items():
            sanitized = attribute_type.replace('|', '\|')
            summary.append(f"| {sanitized} | {feature} |")
        return '\n'.join(summary)


if __name__ == '__main__':
    documentation = DocumentationGenerator()
    documentation.generate_documentation()
    documentation.write_documentation()
