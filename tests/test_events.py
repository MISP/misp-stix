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

_TEST_ATTACK_PATTERN = {
    "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
    "name": "Attack Pattern",
    "type": "mitre-attack-pattern",
    "description": "ATT&CK Tactic",
    "GalaxyCluster": [
        {
            "uuid": "dcaa092b-7de9-4a21-977f-7fcb77e89c48",
            "value": "Access Token Manipulation - T1134",
            "description": "Windows uses access tokens to determine the ownership of a running process.",
            "meta": {
                "external_id": [
                    "CAPEC-633"
                ]
            }
        }
    ]
}


def get_base_event():
    return deepcopy(_BASE_EVENT)


def get_published_event():
    base_event = deepcopy(_BASE_EVENT)
    base_event['published'] = True,
    base_event['publish_timestamp'] = str(int(datetime.now().timestamp()))
    return base_event


def get_event_with_tags():
    event = deepcopy(_BASE_EVENT)
    event['Tag'] = [
        {"name": "tlp:white"},
        {"name": 'misp:tool="misp2stix"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Code Signing - T1116"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"'}
    ]
    event['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN)
    ]
    return event

def get_event_with_attack_pattern_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN)
    ]
    return event
