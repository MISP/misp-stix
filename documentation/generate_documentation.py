# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json


class DocumentationGenerator():
    def __init__(self):
        # content
        self._introduction_filename = 'content/introduction.md'
        self._misp2stix_intro_filename = 'content/misp_to_stix_intro.md'
        self._misp_to_stix1_filename = 'content/misp_to_stix1.md'
        self._attributes_to_stix1_content = 'content/attributes_to_stix1_details.md'
        self._objects_to_stix1_content = 'content/objects_to_stix1_details.md'
        self._galaxies_to_stix1_content = 'content/galaxies_to_stix1_details.md'
        # mapping
        self._misp_attributes_to_stix1_mapping = 'mapping/misp_attributes_to_stix1.json'
        self._misp_custom_attributes_to_stix1_mapping_ = 'mapping/misp_custom_attributes_to_stix1.json'
        self._misp_custom_objects_to_stix1_mapping_ = 'mapping/misp_custom_objects_to_stix1.json'
        self._misp_objects_to_stix1_mapping = 'mapping/misp_objects_to_stix1.json'
        self._misp_galaxies_to_stix1_mapping = 'mapping/misp_galaxies_to_stix1.json'
        # documentation results
        self._misp_attributes_to_stix1 = 'misp_attributes_to_stix1.md'
        self._misp_objects_to_stix1 = 'misp_objects_to_stix1.md'
        self._misp_galaxies_to_stix1 = 'misp_galaxies_to_stix1.md'
        self._output_filename = 'README.md'

    def generate_documentation(self):
        self._generate_introduction()
        self._generate_misp_to_stix_introduction()
        self._generate_misp_to_stix1_documentation()

    def write_documentation(self):
        with open(self._output_filename, 'wt', encoding='utf-8') as f:
            f.write('\n\n'.join(
                [
                    self._introduction,
                    self._misp_to_stix_introduction,
                    self._misp_to_stix1
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
        header = ('STIX',)
        mapping = self._parse_mapping(header, mapping)
        with open(self._misp_custom_attributes_to_stix1_mapping_, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(header, custom_mapping)
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
        mapping = self._parse_mapping(header, mapping)
        with open(self._misp_custom_objects_to_stix1_mapping_, 'rt', encoding='utf-8') as f:
            custom_mapping = json.loads(f.read())
        custom_mapping = self._parse_mapping(header, custom_mapping)
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
        mapping = self._parse_mapping(header, mapping)
        with open(self._galaxies_to_stix1_content, 'rt', encoding='utf-8') as f:
            galaxies_mapping = f.read().format(_galaxies_to_stix1_mapping_=mapping)
        with open(self._misp_galaxies_to_stix1, 'wt', encoding='utf-8') as f:
            f.write(galaxies_mapping)

    def _parse_mapping(self, header, misp2stix_mapping):
        table = []
        for attribute_type, mapping in misp2stix_mapping.items():
            table.append(self._parse_table_line(
                attribute_type,
                header,
                mapping,
                'xml'
            ))
        return '\n'.join(table)

    @staticmethod
    def _parse_table_line(attribute_type, header, mapping, format):
        line = f'- {attribute_type}'
        misp_blob = '\n'.join(f'    {blob}' for blob in json.dumps(mapping['MISP'], indent=4).split('\n'))
        misp_blob = f"  - MISP\n    ```json\n{misp_blob}\n    ```"
        stix_blob = '\n'.join(f"  - {key}\n    ```{format}\n{mapping[key]}\n    ```" for key in header)
        return f'{line}\n{misp_blob}\n{stix_blob}\n'


if __name__ == '__main__':
    documentation = DocumentationGenerator()
    documentation.generate_documentation()
    documentation.write_documentation()
