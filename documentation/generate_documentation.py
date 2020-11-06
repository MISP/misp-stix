# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json


class DocumentationGenerator():
    def __init__(self):
        self._introduction_filename = 'content/introduction.md'
        self._misp2stix_intro_filename = 'content/misp_to_stix_intro.md'
        self._misp_to_stix1_filename = 'content/misp_to_stix1.md'
        self._misp_to_stix1_mapping = 'mapping/misp_attributes_to_stix1.json'
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
            introduction = f.read()
        with open(self._misp_to_stix1_mapping, 'rt', encoding='utf-8') as f:
            mapping = json.loads(f.read())
        header = ('Attribute type', 'MISP', 'STIX')
        misp2stix_mapping = self._parse_mapping(header, mapping)
        self._misp_to_stix1 = f"{introduction}\n\n{misp2stix_mapping}"

    def _parse_mapping(self, header, misp2stix_mapping):
        header_labels = ' </td> <td class="block" style="width:45%"> '
        table = [f"<td> {header_labels.join(header)} </td>"]
        for attribute_type, mapping in misp2stix_mapping.items():
            table.append(self._parse_table_line(
                attribute_type,
                header[2:],
                mapping,
                'xml'
            ))
        table = '\n</tr>\n<tr>\n'.join(table)
        return f'<table style="white-space:nowrap;width:100%;">\n<tr>\n{table}\n</tr>\n</table>'

    @staticmethod
    def _parse_table_line(attribute_type, header, mapping, format):
        line = f'<td> {attribute_type} </td>'
        misp_blob = f"<td>\n\n```json\n{json.dumps(mapping['MISP'], indent=4)}\n```\n\n</td>"
        stix_blob = '\n\n</td>\n<td>\n\n'.join(f"\n```{format}\n{mapping[key]}\n```\n" for key in header)
        return f'{line}\n{misp_blob}\n<td>\n{stix_blob}\n</td>'


if __name__ == '__main__':
    documentation = DocumentationGenerator()
    documentation.generate_documentation()
    documentation.write_documentation()
