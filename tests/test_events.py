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


def get_event_with_attachment_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "attachment",
            "category": "Payload delivery",
            "value": "attachment.test",
            "data": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK"
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


def get_event_with_filename_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "filename",
            "category": "Payload delivery",
            "value": "test_file_name",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Filename test attribute"
        }
    ]
    return event


def get_event_with_hash_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "md5",
            "category": "Payload delivery",
            "value": "b2a5abfeef9e36964281a31e17b57c97",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "MD5 test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "tlsh",
            "category": "Payload delivery",
            "value": "1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "TLSH test attribute"
        }
    ]
    return event


def get_event_with_hash_composite_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "filename|md5",
            "category": "Payload delivery",
            "value": "test_file_name|b2a5abfeef9e36964281a31e17b57c97",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Filename|md5 test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "filename|tlsh",
            "category": "Payload delivery",
            "value": "test_file_name|1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Filename|tlsh test attribute"
        }
    ]
    return event


def get_event_with_hostname_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "hostname",
            "category": "Network activity",
            "value": "circl.lu",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Hostname test attribute"
        }
    ]
    return event


def get_event_with_hostname_port_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "hostname|port",
            "category": "Network activity",
            "value": "circl.lu|8443",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Hostname|port test attribute"
        }
    ]
    return event


def get_event_with_http_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "http-method",
            "category": "Network activity",
            "value": "POST"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "user-agent",
            "category": "Network activity",
            "value": "Mozilla Firefox",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Destination IP | Port test attribute"
        }
    ]
    return event


def get_event_with_ip_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src",
            "category": "Network activity",
            "value": "1.2.3.4",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Source IP test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "category": "Network activity",
            "value": "5.6.7.8",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Destination IP test attribute"
        }
    ]
    return event


def get_event_with_ip_port_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src|port",
            "category": "Network activity",
            "value": "1.2.3.4|1234",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Source IP | Port test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst|port",
            "category": "Network activity",
            "value": "5.6.7.8|5678",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Destination IP | Port test attribute"
        }
    ]
    return event


def get_event_with_mac_address_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "mac-address",
            "category": "Payload delivery",
            "value": "12:34:56:78:90:AB"
        }
    ]
    return event


def get_event_with_malware_sample_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "malware-sample",
            "category": "Payload delivery",
            "value": "oui|8764605c6f388c89096b534d33565802",
            "data": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Malware Sample test attribute"
        }
    ]
    return event


def get_event_with_mutex_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "mutex",
            "category": "Artifacts dropped",
            "value": "MutexTest",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Mutex test attribute"
        }
    ]
    return event


def get_event_with_named_pipe_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "named pipe",
            "category": "Artifacts dropped",
            "value": "\\.\pipe\testpipe"
        }
    ]
    return event


def get_event_with_pattern_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "pattern-in-file",
            "category": "Artifacts dropped",
            "value": "P4tt3rn_1n_f1l3_t3st",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Named pipe test attribute"
        }
    ]
    return event


def get_event_with_port_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "port",
            "category": "Network activity",
            "value": "8443"
        }
    ]
    return event


def get_event_with_regkey_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "regkey",
            "category": "Persistence mechanism",
            "value": "HKLM\Software\mthjk",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Regkey test attribute"
        }
    ]
    return event


def get_event_with_regkey_value_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "regkey|value",
            "category": "Persistence mechanism",
            "value": "HKLM\Software\mthjk|1234567890",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Regkey | value test attribute"
        }
    ]
    return event


def get_event_with_target_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "target-email",
            "value": "target@email.test",
            "category": "Targeting data"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "target-external",
            "value": "external.target",
            "category": "Targeting data"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "target-location",
            "value": "Luxembourg",
            "category": "Targeting data"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "target-machine",
            "value": "target.machine",
            "comment": "Target machine test attribute"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "target-org",
            "value": "Blizzard",
            "category": "Targeting data"
        },
        {
            "uuid": "90bd7dae-b78c-4025-9073-568950c780fb",
            "type": "target-user",
            "value": "iglocska",
            "category": "Targeting data"
        }
    ]
    return event


def get_event_with_test_mechanism_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "snort",
            "category": "Network activity",
            "value": 'alert tcp any any -> any any (msg:"oui")',
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Snort test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "yara",
            "category": "Payload installation",
            "value": 'import "pe" rule single_section{condition:pe.number_of_sections == 1}',
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Yara test attribute"
        }
    ]
    return event


def get_event_with_url_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "url",
            "category": "Network activity",
            "value": "https://misp-project.org/download/",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "URL test attribute"
        }
    ]
    return event


def get_event_with_windows_service_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "windows-service-displayname",
            "category": "Artifacts dropped",
            "value": 'Report for bugs'
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "windows-service-name",
            "category": "Artifacts dropped",
            "value": 'BUGREPORT'
        }
    ]
    return event


def get_event_with_x509_fingerprint_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "x509-fingerprint-md5",
            "category": "Payload delivery",
            "value": "8764605c6f388c89096b534d33565802",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 MD5 fingerprint test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "x509-fingerprint-sha1",
            "category": "Payload delivery",
            "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 SHA1 fingerprint test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "x509-fingerprint-sha256",
            "category": "Payload delivery",
            "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 SHA256 fingerprint test attribute"
        }
    ]
    return event
