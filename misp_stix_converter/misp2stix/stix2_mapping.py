#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stix2.v20.common import (TLP_WHITE as TLP_WHITE_v20, TLP_GREEN as TLP_GREEN_v20,
                              TLP_AMBER as TLP_AMBER_v20, TLP_RED as TLP_RED_v20)
from stix2.v21.common import (TLP_WHITE as TLP_WHITE_v21, TLP_GREEN as TLP_GREEN_v21,
                              TLP_AMBER as TLP_AMBER_v21, TLP_RED as TLP_RED_v21)

attribute_types_mapping = {
    "AS": "_parse_autonomous_system_attribute"
}

tlp_markings_v20 = {
    'tlp:white': TLP_WHITE_v20,
    'tlp:green': TLP_GREEN_v20,
    'tlp:amber': TLP_AMBER_v20,
    'tlp:red': TLP_RED_v20
}

tlp_markings_v21 = {
    'tlp:white': TLP_WHITE_v21,
    'tlp:green': TLP_GREEN_v21,
    'tlp:amber': TLP_AMBER_v21,
    'tlp:red': TLP_RED_v21
}
