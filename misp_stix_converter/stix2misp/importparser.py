# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from pymisp import MISPEvent


class ImportParser():
    def __init__(self):
        self.misp_event = MISPEvent()
        self.galaxies = {}
        self.tags = set()

    def save_file(self):
        event = self.misp_event.to_json()
        with open(self.outputname, 'wt', encoding='utf-8') as f:
            f.write(event)
