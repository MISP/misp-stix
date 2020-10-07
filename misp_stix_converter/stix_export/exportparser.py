# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
from pymisp import MISPEvent


class ExportParser():
    def __init__(self):
        super().__init__()

    def load_event(filename):
        with open(filename, 'rt', encoding='utf-8') as f:
            self.json_event = json.loads(f.read())
        self.filename = filename
