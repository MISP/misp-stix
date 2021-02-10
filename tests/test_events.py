#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
from datetime import date, datetime

################################################################################
#                           DATA STRUCTURES EXAMPLES                           #
################################################################################

_BASE_EVENT = {
    "Event": {
        "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "info": "MISP-STIX-Converter test event",
        "date": date.today().strftime("%Y-%m-%d"),
        "timestamp": str(int(datetime.now().timestamp())),
        "Org": {
            "name": "MISP-Project",
            "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
        },
        "Orgc": {
            "name": "MISP-Project",
            "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
        },
        "Attribute": [],
        "Object": [],
        "Galaxy": [],
        "Tag": []
    }
}

_TEST_ATTACK_PATTERN_GALAXY = {
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

_TEST_COURSE_OF_ACTION_GALAXY = {
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

_TEST_MALWARE_GALAXY = {
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

_TEST_THREAT_ACTOR_GALAXY = {
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

_TEST_TOOL_GALAXY = {
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

_TEST_VULNERABILITY_GALAXY = {
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

_TEST_ASN_OBJECT = {
    "name": "asn",
    "meta-category": "network",
    "description": "Autonomous system object describing an autonomous system",
    "uuid": "5b23c82b-6508-4bdc-b580-045b0a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "AS",
            "object_relation": "asn",
            "value": "AS66642"
        },
        {
            "type": "text",
            "object_relation": "description",
            "value": "AS name"
        },
        {
            "type": "ip-src",
            "object_relation": "subnet-announced",
            "value": "1.2.3.4"
        },
        {
            "type": "ip-src",
            "object_relation": "subnet-announced",
            "value": "8.8.8.8"
        }
    ]
}

_TEST_ATTACK_PATTERN_OBJECT = {
    "name": "attack-pattern",
    "meta-category": "vulnerability",
    "description": "Attack pattern describing a common attack pattern enumeration and classification.",
    "uuid": "7205da54-70de-4fa7-9b34-e14e63fe6787",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "id",
            "value": "9"
        },
        {
            "type": "text",
            "object_relation": "name",
            "value": "Buffer Overflow in Local Command-Line Utilities"
        },
        {
            "type": "text",
            "object_relation": "summary",
            "value": "This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root."
        }
    ]
}

_TEST_BANK_ACCOUNT_OBJECT = {
    "name": "bank-account",
    "meta-category": "financial",
    "description": "An object describing bank account information based on account description from goAML 4.0",
    "uuid": "695e7924-2518-4054-9cea-f82853d37410",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "iban",
            "object_relation": "iban",
            "value": "LU1234567890ABCDEF1234567890",
            "to_ids": True
        },
        {
            "type": "bic",
            "object_relation": "swift",
            "value": "CTBKLUPP"
        },
        {
            "type": "bank-account-nr",
            "object_relation": "account",
            "value": "1234567890"
        },
        {
            "type": "text",
            "object_relation": "institution-name",
            "value": "Central Bank"
        },
        {
            "type": "text",
            "object_relation": "account-name",
            "value": "John Smith's bank account"
        },
        {
            "type": "text",
            "object_relation": "beneficiary",
            "value": "John Smith"
        },
        {
            "type": "text",
            "object_relation": "currency-code",
            "value": "EUR"
        }
    ]
}

_TEST_BTC_WALLET_OBJECT = {
    "name": "btc-wallet",
    "meta-category": "financial",
    "description": "An object to describe a Bitcoin wallet.",
    "uuid": "6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "btc",
            "object_relation": "wallet-address",
            "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
            "to_ids": True
        },
        {
            "type": "float",
            "object_relation": "balance_BTC",
            "value": "2.25036953"
        },
        {
            "type": "float",
            "object_relation": "BTC_received",
            "value": "3.35036953"
        },
        {
            "type": "float",
            "object_relation": "BTC_sent",
            "value": "1.1"
        }
    ]
}

_TEST_COURSE_OF_ACTION_OBJECT = {
    "name": "course-of-action",
    "meta-category": "misc",
    "description": "An object describing a specific measure taken to prevent or respond to an attack.",
    "uuid": "5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "name",
            "value": "Block traffic to PIVY C2 Server (10.10.10.10)"
        },
        {
            "type": "text",
            "object_relation": "type",
            "value": "Perimeter Blocking"
        },
        {
            "type": "text",
            "object_relation": "objective",
            "value": "Block communication between the PIVY agents and the C2 Server"
        },
        {
            "type": "text",
            "object_relation": "stage",
            "value": "Response"
        },
        {
            "type": "text",
            "object_relation": "cost",
            "value": "Low"
        },
        {
            "type": "text",
            "object_relation": "impact",
            "value": "Low"
        },
        {
            "type": "text",
            "object_relation": "efficacy",
            "value": "High"
        },
    ]
}

_TEST_CREDENTIAL_OBJECT = {
    "name": "credential",
    "meta-category": "misc",
    "description": "Credential describes one or more credential(s)",
    "uuid": "5b1f9378-46d4-494b-a4c1-044e0a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "text",
            "value": "MISP default credentials"
        },
        {
            "type": "text",
            "object_relation": "username",
            "value": "misp"
        },
        {
            "type": "text",
            "object_relation": "password",
            "value": "Password1234"
        },
        {
            "type": "text",
            "object_relation": "type",
            "value": "password"
        },
        {
            "type": "text",
            "object_relation": "origin",
            "value": "malware-analysis"
        },
        {
            "type": "text",
            "object_relation": "format",
            "value": "clear-text"
        },
        {
            "type": "text",
            "object_relation": "notification",
            "value": "victim-notified"
        }
    ]
}

_TEST_DOMAIN_IP_OBJECT = {
    "name": "domain-ip",
    "meta-category": "network",
    "description": "A domain and IP address seen as a tuple",
    "uuid": "5ac337df-e078-4e99-8b17-02550a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "domain",
            "object_relation": "domain",
            "value": "circl.lu"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "object_relation": "ip",
            "value": "149.13.33.14"
        }
    ]
}

_TEST_EMAIL_OBJECT = {
    "name": "email",
    "meta-category": "network",
    "description": "Email object describing an email with meta-information",
    "uuid": "5e396622-2a54-4c8d-b61d-159da964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email-src",
            "object_relation": "from",
            "value": "source@email.test"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "email-dst",
            "object_relation": "to",
            "value": "destination@email.test"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "email-dst",
            "object_relation": "cc",
            "value": "cc1@email.test"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "email-dst",
            "object_relation": "cc",
            "value": "cc2@email.test"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "email-reply-to",
            "object_relation": "reply-to",
            "value": "reply-to@email.test"
        },
        {
            "uuid": "90bd7dae-b78c-4025-9073-568950c780fb",
            "type": "email-subject",
            "object_relation": "subject",
            "value": "Email test subject"
        },
        {
            "uuid": "2007ec09-8137-4a71-a3ce-6ef967bebacf",
            "type": "email-attachment",
            "object_relation": "attachment",
            "value": "attachment1.file"
        },
        {
            "uuid": "2d35a390-ccdd-4d6b-a36d-513b05e3682a",
            "type": "email-attachment",
            "object_relation": "attachment",
            "value": "attachment2.file"
        },
        {
            "uuid": "ae3206e4-024c-4988-8455-4aea83971dea",
            "type": "email-x-mailer",
            "object_relation": "x-mailer",
            "value": "x-mailer-test"
        },
        {
            "uuid": "f2fc14de-8d32-4164-bf20-e48ca285ccb2",
            "type": "text",
            "object_relation": "user-agent",
            "value": "Test user agent"
        },
        {
            "uuid": "0d8b91cf-bead-42df-aa6a-a21b98f8c6f7",
            "type": "email-mime-boundary",
            "object_relation": "mime-boundary",
            "value": "Test mime boundary"
        }
    ]
}

_TEST_FILE_OBJECT = {
    "name": "file",
    "meta-category": "file",
    "description": "File object describing a file with meta-information",
    "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "malware-sample",
            "object_relation": "malware-sample",
            "value": "oui|8764605c6f388c89096b534d33565802",
            "data": "UEsDBAoACQAAAPKLQ1AvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAA+dKOF7nSjhedXgLAAEEIQAAAAQhAAAA7ukeownnAQsmsimPVT3qvMUSCRqPjj3xfZpK3MTLpCrssX1AVtxZoMh3ucu5mCxQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAPKLQ1BAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAPnSjhe50o4XnV4CwABBCEAAAAEIQAAAFHTwHeSOtOjQMWS6+0aN1BLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAADyi0NQL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAA+dKOF51eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAADyi0NQQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAPnSjhedXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA=="
        },
        {
            "type": "filename",
            "object_relation": "filename",
            "value": "oui"
        },
        {
            "type": "md5",
            "object_relation": "md5",
            "value": "8764605c6f388c89096b534d33565802"
        },
        {
            "type": "sha1",
            "object_relation": "sha1",
            "value": "46aba99aa7158e4609aaa72b50990842fd22ae86"
        },
        {
            "type": "sha256",
            "object_relation": "sha256",
            "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
        },
        {
            "type": "size-in-bytes",
            "object_relation": "size-in-bytes",
            "value": "35"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "attachment",
            "object_relation": "attachment",
            "value": "non",
            "data": "Tm9uLW1hbGljaW91cyBmaWxlCg=="
        },
        {
            "type": "text",
            "object_relation": "path",
            "value": "/var/www/MISP/app/files/scripts/tmp"
        },
        {
            "type": "text",
            "object_relation": "file-encoding",
            "value": "UTF-8"
        }
    ]
}

_TEST_FILE_FOR_PE_OBJECT = {
    "name": "file",
    "meta-category": "file",
    "description": "File object describing a file with meta-information",
    "uuid": "5ac47782-e1b8-40b6-96b4-02510a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "filename",
            "object_relation": "filename",
            "value": "oui"
        },
        {
            "type": "md5",
            "object_relation": "md5",
            "value": "b2a5abfeef9e36964281a31e17b57c97"
        },
        {
            "type": "sha1",
            "object_relation": "sha1",
            "value": "5898fc860300e228dcd54c0b1045b5fa0dcda502"
        },
        {
            "type": "sha256",
            "object_relation": "sha256",
            "value": "3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8"
        },
        {
            "type": "size-in-bytes",
            "object_relation": "size-in-bytes",
            "value": "1234"
        },
        {
            "type": "float",
            "object_relation": "entropy",
            "value": "1.234"
        }
    ],
    "ObjectReference": [
        {
            "referenced_uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
            "relationship_type": "includes",
            "Object": {
                "uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
                "name": "pe",
                "meta-category": "file"
            }
        }
    ]
}

_TEST_IP_PORT_OBJECT = {
    "name": "ip-port",
    "meta-category": "network",
    "description": "An IP address (or domain) and a port",
    "uuid": "5ac47edc-31e4-4402-a7b6-040d0a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-dst",
            "object_relation": "ip",
            "value": "149.13.33.14"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "port",
            "object_relation": "dst-port",
            "value": "443"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "domain",
            "object_relation": "domain",
            "value": "circl.lu"
        }
    ]
}

_TEST_NETWORK_CONNECTION_OBJECT = {
    "name": "network-connection",
    "meta-category": "network",
    "description": "A local or remote network connection",
    "uuid": "5afacc53-c0b0-4825-a6ee-03c80a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "1.2.3.4"
        },
        {
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "5.6.7.8"
        },
        {
            "type": "port",
            "object_relation": "src-port",
            "value": "8080"
        },
        {
            "type": "port",
            "object_relation": "dst-port",
            "value": "8080"
        },
        {
            "type": "hostname",
            "object_relation": "hostname-dst",
            "value": "circl.lu"
        },
        {
            "type": "text",
            "object_relation": "layer3-protocol",
            "value": "IP"
        },
        {
            "type": "text",
            "object_relation": "layer4-protocol",
            "value": "TCP"
        },
        {
            "type": "text",
            "object_relation": "layer7-protocol",
            "value": "HTTP"
        }
    ]
}

_TEST_NETWORK_SOCKET_OBJECT = {
    "name": "network-socket",
    "meta-category": "network",
    "description": "Network socket object describes a local or remote network connections based on the socket data structure",
    "uuid": "5afb3223-0988-4ef1-a920-02070a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "1.2.3.4"
        },
        {
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "5.6.7.8"
        },
        {
            "type": "port",
            "object_relation": "src-port",
            "value": "8080"
        },
        {
            "type": "port",
            "object_relation": "dst-port",
            "value": "8080"
        },
        {
            "type": "hostname",
            "object_relation": "hostname-dst",
            "value": "circl.lu"
        },
        {
            "type": "text",
            "object_relation": "address-family",
            "value": "AF_FILE"
        },
        {
            "type": "text",
            "object_relation": "domain-family",
            "value": "PF_INET"
        },
        {
            "type": "text",
            "object_relation": "state",
            "value": "listening"
        },
        {
            "type": "text",
            "object_relation": "protocol",
            "value": "TCP"
        }
    ]
}

_TEST_PE_OBJECT = {
    "name": "pe",
    "meta-category": "file",
    "description": "Object describing a Portable Executable",
    "uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "type",
            "value": "exe"
        },
        {
            "type": "datetime",
            "object_relation": "compilation-timestamp",
            "value": "2019-03-16T12:31:22"
        },
        {
            "type": "text",
            "object_relation": "entrypoint-address",
            "value": "5369222868"
        },
        {
            "type": "filename",
            "object_relation": "original-filename",
            "value": "PuTTy"
        },
        {
            "type": "filename",
            "object_relation": "internal-filename",
            "value": "PuTTy"
        },
        {
            "type": "text",
            "object_relation": "file-description",
            "value": "SSH, Telnet and Rlogin client"
        },
        {
            "type": "text",
            "object_relation": "file-version",
            "value": "Release 0.71 (with embedded help)"
        },
        {
            "type": "text",
            "object_relation": "lang-id",
            "value": "080904B0"
        },
        {
            "type": "text",
            "object_relation": "product-name",
            "value": "PuTTy suite"
        },
        {
            "type": "text",
            "object_relation": "product-version",
            "value": "Release 0.71"
        },
        {
            "type": "text",
            "object_relation": "company-name",
            "value": "Simoe Tatham"
        },
        {
            "type": "text",
            "object_relation": "legal-copyright",
            "value": "Copyright \u00a9 1997-2019 Simon Tatham."
        },
        {
            "type": "counter",
            "object_relation": "number-sections",
            "value": "8"
        },
        {
            "type": "imphash",
            "object_relation": "imphash",
            "value": "23ea835ab4b9017c74dfb023d2301c99"
        },
        {
            "type": "impfuzzy",
            "object_relation": "impfuzzy",
            "value": "192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt"
        }
    ],
    "ObjectReference": [
        {
            "referenced_uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
            "relationship_type": "includes",
            "Object": {
                "uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
                "name": "pe-section",
                "meta-category": "file"
            }
        }
    ]
}

_TEST_PE_SECTION_OBJECT = {
    "name": "pe-section",
    "meta-category": "file",
    "description": "Object describing a section of a Portable Executable",
    "uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "name",
            "value": ".rsrc"
        },
        {
            "type": "size-in-bytes",
            "object_relation": "size-in-bytes",
            "value": "305152"
        },
        {
            "type": "float",
            "object_relation": "entropy",
            "value": "7.836462238824369"
        },
        {
            "type": "md5",
            "object_relation": "md5",
            "value": "8a2a5fc2ce56b3b04d58539a95390600",
        },
        {
            "type": "sha1",
            "object_relation": "sha1",
            "value": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf",
        },
        {
            "type": "sha256",
            "object_relation": "sha256",
            "value": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b",
        },
        {
            "type": "sha512",
            "object_relation": "sha512",
            "value": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f",
        },
        {
            "type": "ssdeep",
            "object_relation": "ssdeep",
            "value": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ\/UjHSEuSvK",
        }
    ]
}

_TEST_PERSON_OBJECT = {
    "name": "person",
    "meta-category": "misc",
    "description": "An object which describes a person or an identity.",
    "uuid": "868037d5-d804-4f1d-8016-f296361f9c68",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "first-name",
            "object_relation": "first-name",
            "value": "John"
        },
        {
            "type": "last-name",
            "object_relation": "last-name",
            "value": "Smith"
        },
        {
            "type": "nationality",
            "object_relation": "nationality",
            "value": "USA"
        },
        {
            "type": "passport-number",
            "object_relation": "passport-number",
            "value": "ABA9875413"
        },
        {
            "type": "phone-number",
            "object_relation": "phone-number",
            "value": "0123456789"
        }
    ]
}

_TEST_PROCESS_OBJECT = {
    "name": "process",
    "meta-category": "misc",
    "description": "Object describing a system process.",
    "uuid": "5e39776a-b284-40b3-8079-22fea964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "pid",
            "value": "2510"
        },
        {
            "type": "text",
            "object_relation": "child-pid",
            "value": "1401"
        },
        {
            "type": "text",
            "object_relation": "parent-pid",
            "value": "2107"
        },
        {
            "type": "text",
            "object_relation": "name",
            "value": "test_process.exe"
        },
        {
            "type": "filename",
            "object_relation": "image",
            "value": "TestProcess"
        },
        {
            "type": "port",
            "object_relation": "port",
            "value": "1234"
        }
    ]
}

_TEST_REGISTRY_KEY_OBJECT = {
    "name": "registry-key",
    "meta-category": "file",
    "description": "Registry key object describing a Windows registry key",
    "uuid": "5ac3379c-3e74-44ba-9160-04120a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "regkey",
            "object_relation": "key",
            "value": "hkey_local_machine\\system\\bar\\foo"
        },
        {
            "type": "text",
            "object_relation": "hive",
            "value": "hklm"
        },
        {
            "type": "text",
            "object_relation": "name",
            "value": "RegistryName"
        },
        {
            "type": "text",
            "object_relation": "data",
            "value": "qwertyuiop"
        },
        {
            "type": "text",
            "object_relation": "data-type",
            "value": "REG_SZ"
        },
        {
            "type": "datetime",
            "object_relation": "last-modified",
            "value": "2020-10-25T16:22:00"
        }
    ]
}

_TEST_URL_OBJECT = {
    "name": "url",
    "meta-category": "network",
    "description": "url object describes an url along with its normalized field",
    "uuid": "5ac347ca-dac4-4562-9775-04120a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "url",
            "object_relation": "url",
            "value": "https://www.circl.lu/team"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "domain",
            "object_relation": "domain",
            "value": "circl.lu"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "hostname",
            "object_relation": "host",
            "value": "www.circl.lu"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "ip-dst",
            "object_relation": "ip",
            "value": "149.13.33.14"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "port",
            "object_relation": "port",
            "value": "443"
        }
    ]
}

_TEST_USER_ACCOUNT_OBJECT = {
    "name": "user-account",
    "meta-category": "misc",
    "description": "Object describing an user account",
    "uuid": "5d234f25-539c-4d12-bf93-2c46a964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "username",
            "value": "iglocska"
        },
        {
            "type": "text",
            "object_relation": "user-id",
            "value": "iglocska"
        },
        {
            "type": "text",
            "object_relation": "display-name",
            "value": "Code Monkey"
        },
        {
            "type": "text",
            "object_relation": "password",
            "value": "P4ssw0rd1234!"
        },
        {
            "type": "text",
            "object_relation": "group",
            "value": "viktor-fan"
        },
        {
            "type": "text",
            "object_relation": "group",
            "value": "donald-fan"
        },
        {
            "type": "text",
            "object_relation": "group-id",
            "value": "2004"
        },
        {
            "type": "text",
            "object_relation": "home_dir",
            "value": "/home/iglocska"
        },
    ]
}

_TEST_WHOIS_OBJECT = {
    "name": "whois",
    "meta-category": "network",
    "description": "Whois records information for a domain name or an IP address.",
    "uuid": "5b0d1b61-6c00-4387-a5fa-04370a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "whois-registrar",
            "object_relation": "registrar",
            "value": "Registrar"
        },
        {
            "type": "whois-registrant-email",
            "object_relation": "registrant-email",
            "value": "registrant@email.com"
        },
        {
            "type": "whois-registrant-org",
            "object_relation": "registrant-org",
            "value": "Registrant Org"
        },
        {
            "type": "whois-registrant-name",
            "object_relation": "registrant-name",
            "value": "Registrant Name"
        },
        {
            "type": "whois-registrant-phone",
            "object_relation": "registrant-phone",
            "value": "0123456789"
        },
        {
            "type": "datetime",
            "object_relation": "creation-date",
            "value": "2017-10-01T08:00:00"
        },
        {
            "type": "datetime",
            "object_relation": "modification-date",
            "value": "2020-10-25T16:22:00"
        },
        {
            "type": "datetime",
            "object_relation": "expiration-date",
            "value": "2021-01-01T00:00:00"
        },
        {
            "type": "domain",
            "object_relation": "domain",
            "value": "circl.lu"
        },
        {
            "type": "hostname",
            "object_relation": "nameserver",
            "value": "www.circl.lu"
        },
        {
            "type": "ip-src",
            "object_relation": "ip-address",
            "value": "1.2.3.4"
        },
    ]
}

_TEST_VULNERABILITY_OBJECT = {
    "name": "vulnerability",
    "meta-category": "vulnerability",
    "description": "Vulnerability object describing a common vulnerability",
    "uuid": "5e579975-e9cc-46c6-a6ad-1611a964451a",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "id",
            "value": "CVE-2017-11774"
        },
        {
            "type": "float",
            "object_relation": "cvss-score",
            "value": "6.8"
        },
        {
            "type": "text",
            "object_relation": "summary",
            "value": "Microsoft Outlook allow an attacker to execute arbitrary commands"
        },
        {
            "type": "datetime",
            "object_relation": "created",
            "value": "2017-10-13T07:29:00"
        },
        {
            "type": "datetime",
            "object_relation": "published",
            "value": "2017-10-13T07:29:00"
        },
        {
            "type": "link",
            "object_relation": "references",
            "value": "http://www.securityfocus.com/bid/101098"
        },
        {
            "type": "link",
            "object_relation": "references",
            "value": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11774"
        },
    ]
}

_TEST_WEAKNESS_OBJECT = {
    "name": "weakness",
    "meta-category": "vulnerability",
    "description": "Weakness object describing a common weakness",
    "uuid": "a1285743-3962-40e3-a824-0f21f10f3e19",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "text": "text",
            "object_relation": "id",
            "value": "CWE-119"
        },
        {
            "text": "text",
            "object_relation": "description",
            "value": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer"
        }
    ]
}

_TEST_X509_OBJECT = {
    "name": "x509",
    "meta-category": "network",
    "description": "x509 object describing a X.509 certificate",
    "uuid": "5ac3444e-145c-4749-8467-02550a00020f",
    "timestamp": str(int(datetime.now().timestamp())),
    "Attribute": [
        {
            "type": "text",
            "object_relation": "issuer",
            "value": "Issuer Name"
        },
        {
            "type": "text",
            "object_relation": "pem",
            "value": "RawCertificateInPEMFormat"
        },
        {
            "type": "text",
            "object_relation": "pubkey-info-algorithm",
            "value": "PublicKeyAlgorithm"
        },
        {
            "type": "text",
            "object_relation": "pubkey-info-exponent",
            "value": "2"
        },
        {
            "type": "text",
            "object_relation": "pubkey-info-modulus",
            "value": "C5"
        },
        {
            "type": "text",
            "object_relation": "serial-number",
            "value": "1234567890"
        },
        {
            "type": "text",
            "object_relation": "signature-algorithm",
            "value": "SHA1_WITH_RSA_ENCRYPTION"
        },
        {
            "type": "text",
            "object_relation": "subject",
            "value": "CertificateSubject"
        },
        {
            "type": "datetime",
            "object_relation": "validity-not-before",
            "value": "2020-01-01T00:00:00"
        },
        {
            "type": "datetime",
            "object_relation": "validity-not-after",
            "value": "2021-01-01T00:00:00"
        },
        {
            "type": "text",
            "object_relation": "version",
            "value": "1"
        },
        {
            "type": "x509-fingerprint-md5",
            "object_relation": "x509-fingerprint-md5",
            "value": "b2a5abfeef9e36964281a31e17b57c97"
        },
        {
            "type": "x509-fingerprint-sha1",
            "object_relation": "x509-fingerprint-sha1",
            "value": "5898fc860300e228dcd54c0b1045b5fa0dcda502"
        },
    ]
}

################################################################################
#                               BASE EVENT TESTS                               #
################################################################################


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
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY)
    ]
    return event


################################################################################
#                                GALAXIES TESTS                                #
################################################################################


def get_event_with_attack_pattern_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY)
    ]
    return event


def get_event_with_course_of_action_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    return event


def get_event_with_malware_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE_GALAXY)
    ]
    return event


def get_event_with_threat_actor_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_THREAT_ACTOR_GALAXY)
    ]
    return event


def get_event_with_tool_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_TOOL_GALAXY)
    ]
    return event


def get_event_with_vulnerability_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_VULNERABILITY_GALAXY)
    ]
    return event


################################################################################
#                               ATTRIBUTES TESTS                               #
################################################################################

_INDICATOR_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "domain",
    "category": "Network activity",
    "value": "circl.lu",
    "timestamp": str(int(datetime.now().timestamp())),
    "comment": "Domain test attribute",
    "to_ids": True
}

_NON_INDICATOR_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "vulnerability",
    "category": "External analysis",
    "value": "CVE-2017-11774",
    "timestamp": str(int(datetime.now().timestamp())),
    "comment": "Vulnerability test attribute"
}

_OBSERVABLE_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "AS",
    "category": "Network activity",
    "timestamp": str(int(datetime.now().timestamp())),
    "value": "AS174"
}


def get_embedded_indicator_attribute_galaxy():
    attribute = deepcopy(_INDICATOR_ATTRIBUTE)
    attribute['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY),
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [attribute]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE_GALAXY)
    ]
    return event


def get_embedded_non_indicator_attribute_galaxy():
    attribute = deepcopy(_NON_INDICATOR_ATTRIBUTE)
    attribute['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY),
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [attribute]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY),
        deepcopy(_TEST_MALWARE_GALAXY)
    ]
    return event


def get_embedded_observable_attribute_galaxy():
    attribute = deepcopy(_OBSERVABLE_ATTRIBUTE)
    attribute['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY)
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [attribute]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE_GALAXY)
    ]
    return event


def get_event_with_as_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_OBSERVABLE_ATTRIBUTE)
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


def get_event_with_custom_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "btc",
            "category": "Financial fraud",
            "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Btc test attribute",
            "to_ids": True
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "iban",
            "category": "Financial fraud",
            "value": "LU1234567890ABCDEF1234567890",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "IBAN test attribute",
            "to_ids": True
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "phone-number",
            "category": "Person",
            "value": "0123456789"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "passport-number",
            "category": "Person",
            "value": "ABA9875413"
        },
    ]
    return event


def get_event_with_domain_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_INDICATOR_ATTRIBUTE)
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
            "comment": "Domain|ip test attribute",
            "to_ids": True
        }
    ]
    return event


def get_event_with_email_attachment_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email-attachment",
            "category": "Payload delivery",
            "value": "email_attachment.test",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Email attachment test attribute",
            "to_ids": True
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
            "comment": "Source email address test attribute",
            "to_ids": True
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "email-dst",
            "category": "Payload delivery",
            "value": "dst@email.test",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Destination email address test attribute",
            "to_ids": True
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
            "comment": "Filename test attribute",
            "to_ids": True
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
            "comment": "MD5 test attribute",
            "to_ids": True
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "tlsh",
            "category": "Payload delivery",
            "value": "1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "TLSH test attribute",
            "to_ids": True
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
            "comment": "Filename|md5 test attribute",
            "to_ids": True
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "filename|tlsh",
            "category": "Payload delivery",
            "value": "test_file_name|1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Filename|tlsh test attribute",
            "to_ids": True
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
            "comment": "Hostname test attribute",
            "to_ids": True
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
            "comment": "Hostname|port test attribute",
            "to_ids": True
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
            "comment": "User-agent test attribute"
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
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Source IP test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "category": "Network activity",
            "value": "5.6.7.8",
            "to_ids": True,
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
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Source IP | Port test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst|port",
            "category": "Network activity",
            "value": "5.6.7.8|5678",
            "to_ids": True,
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
            "value": "12:34:56:78:90:AB",
            "timestamp": str(int(datetime.now().timestamp())),
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
            "to_ids": True,
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
            "to_ids": True,
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
            "to_ids": True,
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
            "to_ids": True,
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
            "to_ids": True,
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
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Snort test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "yara",
            "category": "Payload installation",
            "value": 'import "pe" rule single_section{condition:pe.number_of_sections == 1}',
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Yara test attribute"
        }
    ]
    return event


def get_event_with_undefined_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "comment",
            "category": "Other",
            "value": "Test comment from a STIX header",
            "comment": "Imported from STIX header description"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "comment",
            "category": "Other",
            "value": "Test comment for the journal entry"
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
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "URL test attribute"
        }
    ]
    return event


def get_event_with_vulnerability_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_NON_INDICATOR_ATTRIBUTE)
    ]
    return event


def get_event_with_weakness_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "weakness",
            "category": "External analysis",
            "value": "CWE-25",
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "Weakness test attribute"
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
            "value": "Report for bugs"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "windows-service-name",
            "category": "Artifacts dropped",
            "value": "BUGREPORT"
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
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 MD5 fingerprint test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "x509-fingerprint-sha1",
            "category": "Payload delivery",
            "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 SHA1 fingerprint test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "x509-fingerprint-sha256",
            "category": "Payload delivery",
            "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
            "to_ids": True,
            "timestamp": str(int(datetime.now().timestamp())),
            "comment": "X509 SHA256 fingerprint test attribute"
        }
    ]
    return event


################################################################################
#                              MISP OBJECTS TESTS                              #
################################################################################

def get_embedded_indicator_object_galaxy():
    event = deepcopy(_BASE_EVENT)
    misp_object = deepcopy(_TEST_ASN_OBJECT)
    misp_object['Attribute'][0]['Galaxy'] = [deepcopy(_TEST_MALWARE_GALAXY)]
    misp_object['Attribute'][1]['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    event['Event']['Object'] = [misp_object]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_TOOL_GALAXY),
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    return event


def get_embedded_non_indicator_object_galaxy():
    event = deepcopy(_BASE_EVENT)
    coa_object = deepcopy(_TEST_COURSE_OF_ACTION_OBJECT)
    coa_object['Attribute'][0]['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY)
    ]
    coa_object['Attribute'][1]['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    ttp_object = deepcopy(_TEST_VULNERABILITY_OBJECT)
    ttp_object['Attribute'][0]['Galaxy'] = [deepcopy(_TEST_MALWARE_GALAXY)]
    ttp_object['Attribute'][1]['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    event['Event']['Object'] = [
        coa_object,
        ttp_object
    ]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY),
        deepcopy(_TEST_TOOL_GALAXY)
    ]
    return event


def get_embedded_object_galaxy_with_multiple_clusters():
    event = deepcopy(_BASE_EVENT)
    misp_object = deepcopy(_TEST_ASN_OBJECT)
    misp_object['Attribute'][0]['Galaxy'] = [deepcopy(_TEST_MALWARE_GALAXY)]
    misp_object['Attribute'][1]['Galaxy'] = [
        {
            "uuid": "d752161c-78f6-11e7-a0ea-bfa79b407ce4",
            "name": "Malware",
            "type": "mitre-malware",
            "description": "Name of ATT&CK software",
            "GalaxyCluster": [
                {
                    "uuid": "8787e86d-8475-4f13-acea-d33eb83b6105",
                    "value": "Winnti for Linux - S0430",
                    "description": "Winnti for Linux is a trojan designed specifically for targeting Linux systems.",
                    "meta": {
                        "synonyms": [
                            "Winnti for Linux"
                        ]
                    }
                }
            ]
        }
    ]
    event['Event']['Object'] = [misp_object]
    return event


def get_embedded_observable_object_galaxy():
    event = deepcopy(_BASE_EVENT)
    misp_object = deepcopy(_TEST_ASN_OBJECT)
    misp_object['Attribute'][0]['Galaxy'] = [deepcopy(_TEST_MALWARE_GALAXY)]
    event['Event']['Object'] = [misp_object]
    event['Event']['Galaxy'] = [deepcopy(_TEST_TOOL_GALAXY)]
    return event


def get_event_with_asn_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_ASN_OBJECT)
    ]
    return event


def get_event_with_attack_pattern_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_ATTACK_PATTERN_OBJECT)
    ]
    return event


def get_event_with_course_of_action_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_COURSE_OF_ACTION_OBJECT)
    ]
    return event


def get_event_with_credential_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_CREDENTIAL_OBJECT)
    ]
    return event


def get_event_with_custom_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_BANK_ACCOUNT_OBJECT),
        deepcopy(_TEST_BTC_WALLET_OBJECT),
        deepcopy(_TEST_PERSON_OBJECT)
    ]
    return event


def get_event_with_domain_ip_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_DOMAIN_IP_OBJECT)
    ]
    return event


def get_event_with_email_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_EMAIL_OBJECT)
    ]
    return event


def get_event_with_file_object_with_artifact():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_FILE_OBJECT)
    ]
    return event


def get_event_with_file_and_pe_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_FILE_FOR_PE_OBJECT),
        deepcopy(_TEST_PE_OBJECT),
        deepcopy(_TEST_PE_SECTION_OBJECT)
    ]
    return event


def get_event_with_file_object():
    event = deepcopy(_BASE_EVENT)
    file_object = deepcopy(_TEST_FILE_OBJECT)
    file_object['Attribute'] = [{field: value for field, value in attribute.items() if field != 'data'} for attribute in file_object['Attribute']]
    event['Event']['Object'] = [
        file_object
    ]
    return event


def get_event_with_ip_port_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_IP_PORT_OBJECT)
    ]
    return event


def get_event_with_network_connection_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_NETWORK_CONNECTION_OBJECT)
    ]
    return event


def get_event_with_network_socket_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_NETWORK_SOCKET_OBJECT)
    ]
    return event


def get_event_with_process_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_PROCESS_OBJECT)
    ]
    return event


def get_event_with_registry_key_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_REGISTRY_KEY_OBJECT)
    ]
    return event


def get_event_with_url_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_URL_OBJECT)
    ]
    return event


def get_event_with_user_account_objects():
    event = deepcopy(_BASE_EVENT)
    unix_user_account = deepcopy(_TEST_USER_ACCOUNT_OBJECT)
    unix_user_account['Attribute'].append(
        {
            "type": "text",
            "object_relation": "account-type",
            "value": "unix"
        }
    )
    windows_user_account = deepcopy(_TEST_USER_ACCOUNT_OBJECT)
    windows_user_account['Attribute'].append(
        {
            "type": "text",
            "object_relation": "account-type",
            "value": "windows-local"
        },
    )
    event['Event']['Object'] = [
        deepcopy(_TEST_USER_ACCOUNT_OBJECT),
        unix_user_account,
        windows_user_account
    ]
    return event


def get_event_with_vulnerability_and_weakness_objects():
    event = deepcopy(_BASE_EVENT)
    weakness = deepcopy(_TEST_WEAKNESS_OBJECT)
    vulnerability = deepcopy(_TEST_VULNERABILITY_OBJECT)
    vulnerability['ObjectReference'] = [
        {
            "referenced_uuid": weakness['uuid'],
            "relationship_type": "weakened-by"
        }
    ]
    event['Event']['Object'] = [
        vulnerability,
        weakness
    ]
    return event


def get_event_with_vulnerability_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_VULNERABILITY_OBJECT)
    ]
    return event


def get_event_with_weakness_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_WEAKNESS_OBJECT)
    ]
    return event


def get_event_with_whois_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_WHOIS_OBJECT)
    ]
    return event


def get_event_with_x509_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_X509_OBJECT)
    ]
    return event
