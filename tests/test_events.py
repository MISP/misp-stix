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

_TEST_COURSE_OF_ACTION = {
    "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e",
    "name": "Course of Action",
    "type": "mitre-course-of-action",
    "description": "ATT&CK Mitigation",
    "GalaxyCluster": [
        {
            "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
            "value": "Automated Exfiltration Mitigation - T1020",
            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
        }
    ]
}

_TEST_MALWARE = {
    "uuid": "d752161c-78f6-11e7-a0ea-bfa79b407ce4",
    "name": "Malware",
    "type": "mitre-malware",
    "description": "Name of ATT&CK software",
    "GalaxyCluster": [
        {
            "uuid": "b8eb28e4-48a6-40ae-951a-328714f75eda",
            "value": "BISCUIT - S0017",
            "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
            "meta": {
                "synonyms": [
                    "BISCUIT"
                ]
            }
        }
    ]
}

_TEST_THREAT_ACTOR = {
    "uuid": "698774c7-8022-42c4-917f-8d6e4f06ada3",
    "name": "Threat Actor",
    "type": "threat-actor",
    "description": "Threat actors are characteristics of malicious actors.",
    "GalaxyCluster": [
        {
            "uuid": "11e17436-6ede-4733-8547-4ce0254ea19e",
            "value": "Cutting Kitten",
            "description": "These convincing profiles form a self-referenced network of seemingly established LinkedIn users.",
            "meta": {
                "cfr-type-of-incident": [
                    "Denial of service"
                ]
            }
        }
    ]
}

_TEST_TOOL = {
    "uuid": "d5cbd1a2-78f6-11e7-a833-7b9bccca9649",
    "name": "Tool",
    "type": "mitre-tool",
    "description": "Name of ATT&CK software",
    "GalaxyCluster": [
        {
            "uuid": "bba595da-b73a-4354-aa6c-224d4de7cb4e",
            "value": "cmd - S0106",
            "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities."
        }
    ]
}

_TEST_VULNERABILITY = {
    "uuid": "fda8c7c2-f45a-11e7-9713-e75dac0492df",
    "name": "Branded Vulnerability",
    "type": "branded-vulnerability",
    "description": "List of known vulnerabilities and exploits",
    "GalaxyCluster": [
        {
            "uuid": "a1640081-aa8d-4070-84b2-d23e2ae82799",
            "value": "Ghost",
            "description": "The GHOST vulnerability is a serious weakness in the Linux glibc library.",
            "meta": {
                "aliases": [
                    "CVE-2015–0235"
                ]
            }
        }
    ]

}

def get_base_event():
    return deepcopy(_BASE_EVENT)


def get_published_event():
    base_event = deepcopy(_BASE_EVENT)
    base_event['Event']['published'] = True
    base_event['Event']['publish_timestamp'] = str(int(datetime.now().timestamp()))
    return base_event


def get_event_with_tags():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Tag'] = [
        {"name": "tlp:white"},
        {"name": 'misp:tool="misp2stix"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Code Signing - T1116"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"'}
    ]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN)
    ]
    return event

def get_event_with_attack_pattern_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN)
    ]
    return event

def get_event_with_course_of_action_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION)
    ]
    return event

def get_event_with_malware_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE)
    ]
    return event

def get_event_with_threat_actor_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_THREAT_ACTOR)
    ]
    return event

def get_event_with_tool_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_TOOL)
    ]
    return event

def get_event_with_vulnerability_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_VULNERABILITY)
    ]
    return event

def get_event_with_as_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "AS",
            "category": "Network activity",
            "value": "AS174"
        }
    ]
    return event

def get_event_with_domain_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "domain",
            "category": "Network activity",
            "value": "circl.lu",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Domain test attribute"
        }
    ]
    return event

def get_event_with_domain_ip_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "domain|ip",
            "category": "Network activity",
            "value": "circl.lu|149.13.33.14",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Domain|ip test attribute"
        }
    ]
    return event

def get_event_with_email_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email-src",
            "category": "Payload delivery",
            "value": "src@email.test",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Source email address test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "email-dst",
            "category": "Payload delivery",
            "value": "dst@email.test",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Destination email address test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "email-subject",
            "category": "Payload delivery",
            "value": "Test Subject"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "email-reply-to",
            "category": "Payload delivery",
            "value": "reply-to@email.test"
        }
    ]
    return event
