#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
from datetime import date, datetime

_BASE_EVENT = {
    "Event": {
        "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
        "info": "MISP-STIX-Converter test event",
        "date": date.today().strftime("%Y-%m-%d"),
        "timestamp": str(int(datetime.now().timestamp())),
        "Org": {
            "name": "MISP-Project"
        },
        "Orgc": {
            "name": "MISP-Project"
        },
        "Attribute": [],
        "Object": [],
        "Galaxy": [],
        "Tag": []
    }
}


def get_base_event():
    return deepcopy(_BASE_EVENT)


def get_published_event():
    base_event = deepcopy(_BASE_EVENT)
    base_event['published'] = True,
    base_event['publish_timestamp'] = str(int(datetime.now().timestamp()))
    return base_event
