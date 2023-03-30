#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from copy import deepcopy
from pathlib import Path

_TESTFILES_PATH = Path(__file__).parent.resolve() / 'attachment_test_files'

################################################################################
#                           DATA STRUCTURES EXAMPLES                           #
################################################################################

_BASE_EVENT = {
    "Event": {
        "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "info": "MISP-STIX-Converter test event",
        "date": "2020-10-25",
        "timestamp": "1603642920",
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

_EVENT_FOR_ESCAPING_TESTS = {
    "Event": {
        "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "info": "MISP-STIX-Converter test event",
        "date": "2020-10-25",
        "timestamp": "1603642920",
        "Org": {
            "name": "MISP-Project",
            "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
        },
        "Orgc": {
            "name": "MISP-Project",
            "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
        },
        "Attribute": [
            {
                "uuid": "6879f5f7-f7c7-442d-a454-673b49af2685",
                "type": "AS",
                "category": "Network activity",
                "timestamp": "1603642920",
                "value": "AS174'",
                "to_ids": True
            },
            {
                "uuid": "38ade645-78f0-43c4-bc84-9ddebf27049a",
                "type": "attachment",
                "category": "Payload delivery",
                "value": "attachment.test",
                "data": "ZWNobyAiREFOR0VST1VTIE'1BTFdBUkUiIAoK",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "type": "domain",
                "category": "Network activity",
                "value": "broken.circl's.domain",
                "timestamp": "1603642920",
                "comment": "Domain test attribute",
                "to_ids": True
            },
            {
                "uuid": "3a51a1a7-81b6-49cc-84c2-c364f1dbd8ec",
                "type": "domain|ip",
                "category": "Network activity",
                "value": "circl's.wrong.domain|149.13.33.14",
                "timestamp": "1603642920",
                "comment": "Domain|ip test attribute",
                "to_ids": True
            },
            {
                "uuid": "304aa49b-ab4b-4578-ab0f-85a12fa008dc",
                "type": "email",
                "category": "Payload delivery",
                "value": "address'@email.test",
                "timestamp": "1603642920",
                'to_ids': True
            },
            {
                "uuid": "e8166fc1-4c84-4a4b-954b-269bcb2f0568",
                "type": "email-attachment",
                "category": "Payload delivery",
                "value": "email's attachment.test",
                "timestamp": "1603642920",
                "comment": "Email attachment test attribute",
                "to_ids": True
            },
            {
                "uuid": "98c5c016-5823-4b2b-968d-eb5e6dfae12e",
                "type": "email-body",
                "category": "Payload delivery",
                "value": "Email's test",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "6734bcd2-0c3f-4da3-9c56-b518339a1522",
                "type": "email-dst",
                "category": "Payload delivery",
                "value": "dst'@email.test",
                "timestamp": "1603642920",
                "comment": "Destination email address test attribute",
                "to_ids": True
            },
            {
                "uuid": "978aa19d-c7ef-477a-8f26-a424e4fbbb54",
                "type": "email-header",
                "category": "Payload delivery",
                "value": 'from mail.example.com ("198.51.100.3") by smtp.gmail.com',
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
                "type": "email-reply-to",
                "category": "Payload delivery",
                "value": "reply-to'@email.test",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "8f121697-d112-4742-b5a2-2e1d711c4af5",
                "type": "email-src",
                "category": "Payload delivery",
                "value": "src'@email.test",
                "timestamp": "1603642920",
                "comment": "Source email address test attribute",
                "to_ids": True
            },
            {
                "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                "type": "email-subject",
                "category": "Payload delivery",
                "value": "Email's Subject",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "f09d8496-e2ba-4250-878a-bec9b85c7e96",
                "type": "email-x-mailer",
                "category": "Payload delivery",
                "value": "Email's X-Mailer",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "f037ccb0-195b-4270-bc3d-9b55caf9d0bf",
                "type": "filename",
                "category": "Payload delivery",
                "value": "File's name.test",
                "timestamp": "1603642920",
                "comment": "Filename test attribute",
                "to_ids": True
            },
            {
                "uuid": "0a8d5fe9-8265-41eb-8672-7119d87148a4",
                "type": "md5",
                "category": "Payload delivery",
                "value": '"b2a5abfeef9e36964281a31e17b57c97"',
                "timestamp": "1603642920",
                "comment": "MD5 test attribute",
                "to_ids": True
            },
            {
                "uuid": "9701e31a-b461-49d2-a18c-05bd18ecac8c",
                "type": "filename|md5",
                "category": "Payload delivery",
                "value": "File's name.test|b2a5abfeef9e36964281a31e17b57c97",
                "timestamp": "1603642920",
                "comment": "Filename | MD5 test attribute",
                "to_ids": True
            },
            {
                "uuid": "ee9da65d-1179-46a6-85ff-588f46f6b909",
                "type": "hostname",
                "category": "Network activity",
                "value": "circl's.wrong.hostname",
                "timestamp": "1603642920",
                "comment": "Hostname test attribute",
                "to_ids": True
            },
            {
                "uuid": "7ad6e3c2-a687-4101-b427-ea2b3860c518",
                "type": "hostname|port",
                "category": "Network activity",
                "value": "'circl.lu'|8443",
                "timestamp": "1603642920",
                "comment": "Hostname|port test attribute",
                "to_ids": True
            },
            {
                "uuid": "989e1c92-ba53-4071-9faa-4db909cb84bb",
                "type": "http-method",
                "category": "Network activity",
                "value": '"POST"',
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "d706e432-149e-4074-b62d-6f78cb69c335",
                "type": "ip-src",
                "category": "Network activity",
                "value": '"1.2.3.4"',
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Source IP test attribute"
            },
            {
                "uuid": "e80260cb-1db4-4f73-8a71-9f0032682fee",
                "type": "ip-src|port",
                "category": "Network activity",
                "value": "'1.2.3.4'|1234",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Source IP | Port test attribute"
            },
            {
                "uuid": "99d23a7d-48d0-4f9a-b7b5-b90ebda9fd31",
                "type": "mac-address",
                "category": "Payload delivery",
                "value": "'12:34:56:78:90:AB'",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "2ea3a395-6b9f-4927-bc85-b33310f0b1bf",
                "type": "malware-sample",
                "category": "Payload delivery",
                "value": "oui|8764605c6f388c89096b534d33565802",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Malware Sample test attribute"
            },
            {
                "uuid": "0c4fa6dc-7476-4712-b84a-5ecc5075f930",
                "type": "mutex",
                "category": "Artifacts dropped",
                "value": "Mutex'Test",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Mutex test attribute"
            },
            {
                "uuid": "3d6a260e-9eb3-47c9-b631-c71a2911eb35",
                "type": "port",
                "category": "Network activity",
                "value": "'8443'",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "2728a5a4-3a66-45fc-86b4-f57fd51b3f5a",
                "type": "regkey",
                "category": "Persistence mechanism",
                "value": "'HKLM\Software\mthjk'",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Regkey test attribute"
            },
            {
                "uuid": "a0ee745a-cb8f-440f-a295-181109aafec4",
                "type": "regkey|value",
                "category": "Persistence mechanism",
                "value": "'HKLM\Software\mthjk'|%DATA%\\1234567890",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "Regkey | value test attribute"
            },
            {
                "uuid": "dd5aaa8b-60ca-411e-a5d2-aae772732705",
                "type": "size-in-bytes",
                "value": "'1234'",
                "category": "Other",
                "timestamp": "1603642920",
                "to_ids": True
            },
            {
                "uuid": "2ed3314c-1253-4841-ace9-188313fcefe2",
                "type": "url",
                "category": "Network activity",
                "value": "'https://misp-project.org/download/'",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "URL test attribute"
            },
            {
                "uuid": "09fa6628-1bef-40e1-8a63-fca80229b15c",
                "type": "user-agent",
                "category": "Network activity",
                "value": '"Mozilla Firefox"',
                "timestamp": "1603642920",
                "comment": "User-agent test attribute",
                "to_ids": True
            },
            {
                "uuid": "4e47891d-8d57-4e7f-9d5e-e3bfada58228",
                "type": "x509-fingerprint-md5",
                "category": "Payload delivery",
                "value": "'8764605c6f388c89096b534d33565802'",
                "to_ids": True,
                "timestamp": "1603642920",
                "comment": "X509 MD5 fingerprint test attribute"
            }
        ],
        "Object": [
            {
                "name": "asn",
                "meta-category": "network",
                "description": "Autonomous system object describing an autonomous system",
                "uuid": "5b23c82b-6508-4bdc-b580-045b0a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "AS",
                        "object_relation": "asn",
                        "value": "AS66642",
                        "to_ids": True
                    },
                    {
                        "type": "text",
                        "object_relation": "description",
                        "value": "Test's AS"
                    }
                ]
            },
            {
                "name": "credential",
                "meta-category": "misc",
                "description": "Credential describes one or more credential(s)",
                "uuid": "5b1f9378-46d4-494b-a4c1-044e0a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "text",
                        "value": "MISP's credentials"
                    },
                    {
                        "type": "text",
                        "object_relation": "username",
                        "value": "misp",
                        "to_ids": True
                    }
                ]
            },
            {
                "name": "domain-ip",
                "meta-category": "network",
                "description": "A domain and IP address seen as a tuple",
                "uuid": "dc624447-684a-488f-9e16-f78f717d8efd",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "63fa4060-98d3-4768-b18d-cfbc52f2d0ff",
                        "type": "domain",
                        "object_relation": "domain",
                        "value": "wrong.circl's.domain",
                        "to_ids": True
                    },
                    {
                        "uuid": "fcbaf339-615a-409c-915f-034420dc90ca",
                        "type": "ip-dst",
                        "object_relation": "ip",
                        "value": "149.33.33.44"
                    },
                ]
            },
            {
                "name": "email",
                "meta-category": "network",
                "description": "Email object describing an email with meta-information",
                "uuid": "5e396622-2a54-4c8d-b61d-159da964451a",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "email-src",
                        "object_relation": "from",
                        "value": "donald.duck@disney.com",
                        "to_ids": True
                    },
                    {
                        "uuid": "3766d98d-d162-44d4-bc48-9518a2e48898",
                        "type": "email-src-display-name",
                        "object_relation": "from-display-name",
                        "value": 'The "Duck"'
                    },
                    {
                        "uuid": "aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
                        "type": "email-dst",
                        "object_relation": "to",
                        "value": "jdoe@random.org"
                    },
                    {
                        "uuid": "3a93a3ef-fd04-4ce5-98f5-f53609b39b82",
                        "type": "email-dst-display-name",
                        "object_relation": "to-display-name",
                        "value": "John Doe'"
                    }
                ]
            },
            {
                "name": "file",
                "meta-category": "file",
                "description": "File object describing a file with meta-information",
                "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "filename",
                        "object_relation": "filename",
                        "value": 'My Little "Poney".jpg',
                        "to_ids": True
                    },
                    {
                        "type": "size-in-bytes",
                        "object_relation": "size-in-bytes",
                        "value": "12345"
                    }
                ]
            },
            {
                "name": "ip-port",
                "meta-category": "network",
                "description": "An IP address (or domain) and a port",
                "uuid": "5ac47edc-31e4-4402-a7b6-040d0a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "ip-dst",
                        "object_relation": "ip",
                        "value": "149.33.33.44",
                        "to_ids": True
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
                        "value": "wrong.circl's.domain"
                    }
                ]
            },
            {
                "name": "mutex",
                "meta-category": "misc",
                "description": "Object to describe mutual exclusion locks (mutex) as seen in memory or computer program",
                "uuid": "b0f55591-6a63-4fbd-a169-064e64738d95",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "name",
                        "value": 'The "Mutex"',
                        "to_ids": True
                    },
                    {
                        "type": "text",
                        "object_relation": "description",
                        "value": "John Doe's mutex"
                    }
                ]
            },
            {
                "name": "network-connection",
                "meta-category": "network",
                "description": "A local or remote network connection",
                "uuid": "5afacc53-c0b0-4825-a6ee-03c80a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "ip-src",
                        "object_relation": "ip-src",
                        "value": '"1.2.3.4"',
                        "to_ids": True
                    },
                    {
                        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                        "type": "ip-dst",
                        "object_relation": "ip-dst",
                        "value": "'5.6.7.8'"
                    }
                ]
            },
            {
                "name": "network-socket",
                "meta-category": "network",
                "description": "Network socket object describes a local or remote network connections based on the socket data structure",
                "uuid": "5afb3223-0988-4ef1-a920-02070a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                        "type": "ip-dst",
                        "object_relation": "ip-dst",
                        "value": "5.6.7.8",
                        "to_ids": True
                    },
                    {
                        "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
                        "type": "hostname",
                        "object_relation": "hostname-dst",
                        "value": "wrong.circl's.hostname"
                    }
                ]
            },
            {
                "name": "pe",
                "meta-category": "file",
                "description": "Object describing a Portable Executable",
                "uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "type",
                        "value": "exe"
                    },
                    {
                        "type": "filename",
                        "object_relation": "original-filename",
                        "value": 'The "PuTTy"',
                        "to_ids": True
                    },
                    {
                        "type": "text",
                        "object_relation": "file-description",
                        "value": "John Doe's favorite SSH client"
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
            },
            {
                "name": "pe-section",
                "meta-category": "file",
                "description": "Object describing a section of a Portable Executable",
                "uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "name",
                        "value": "PE's first section"
                    }
                ]
            },
            {
                "name": "process",
                "meta-category": "misc",
                "description": "Object describing a system process.",
                "uuid": "5e39776a-b284-40b3-8079-22fea964451a",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "text",
                        "object_relation": "pid",
                        "value": "2510",
                        "to_ids": True
                    },
                    {
                        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
                        "type": "text",
                        "object_relation": "name",
                        "value": "Jonh's Process"
                    }
                ]
            },
            {
                "name": "registry-key",
                "meta-category": "file",
                "description": "Registry key object describing a Windows registry key",
                "uuid": "5ac3379c-3e74-44ba-9160-04120a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "regkey",
                        "object_relation": "key",
                        "value": "hkey_local_machine\\system\\bar\\foo",
                        "to_ids": True
                    },
                    {
                        "type": "text",
                        "object_relation": "name",
                        "value": "Registry's Name"
                    }
                ]
            },
            {
                "name": "url",
                "meta-category": "network",
                "description": "url object describes an url along with its normalized field",
                "uuid": "5ac347ca-dac4-4562-9775-04120a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "url",
                        "object_relation": "url",
                        "value": "https://www.wrong.circl's.url",
                        "to_ids": True
                    },
                    {
                        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                        "type": "domain",
                        "object_relation": "domain",
                        "value": "circl.lu"
                    }
                ]
            },
            {
                "name": "user-account",
                "meta-category": "misc",
                "description": "Object describing an user account",
                "uuid": "5d234f25-539c-4d12-bf93-2c46a964451a",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "user-id",
                        "value": "iglocska",
                        "to_ids": True
                    },
                    {
                        "type": "text",
                        "object_relation": "display-name",
                        "value": "Cod'Monkey"
                    },
                    {
                        "type": "text",
                        "object_relation": "password",
                        "value": "P4ssw0rd1234!"
                    }
                ]
            },
            {
                "name": "x509",
                "meta-category": "network",
                "description": "x509 object describing a X.509 certificate",
                "uuid": "5ac3444e-145c-4749-8467-02550a00020f",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "issuer",
                        "value": "Issuer's Name"
                    },
                    {
                        "type": "text",
                        "object_relation": "serial-number",
                        "value": "1234567890",
                        "to_ids": True
                    },
                    {
                        "type": "x509-fingerprint-md5",
                        "object_relation": "x509-fingerprint-md5",
                        "value": "b2a5abfeef9e36964281a31e17b57c97"
                    }
                ]
            }
        ]
    }
}

_TEST_EVENT_REPORT = {
    "Attribute": [
        {
            "type": "ip-src",
            "category": "Network activity",
            "to_ids": True,
            "uuid": "f9b286a9-3ed6-4ace-a60c-a5fe6529a783",
            "timestamp": "1603642920",
            "value": "8.8.8.8"
        },
        {
            "type": "attachment",
            "category": "Payload delivery",
            "to_ids": False,
            "uuid": "f715be9f-845f-4d8c-8dce-852b353b3488",
            "timestamp": "1603642920",
            "value": "google_screenshot.png"
        }
    ],
    "Object": [
        {
            "name": "domain-ip",
            "meta-category": "network",
            "description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
            "uuid": "f91abf56-b017-462a-849f-d03ae0187498",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "domain",
                    "category": "Network activity",
                    "object_relation": "domain",
                    "to_ids": True,
                    "uuid": "07a4c4aa-7380-44b5-82d4-06628ee3afba",
                    "timestamp": "1603642920",
                    "value": "google.com"
                },
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "object_relation": "ip",
                    "to_ids": True,
                    "uuid": "7ef43014-e2d6-4a13-b8fd-129fe4009310",
                    "timestamp": "1603642920",
                    "value": "8.8.8.8"
                }
            ]
        }
    ],
    "EventReport": [
        {
            "uuid": "0d8fdacd-5ed2-42ca-a286-d4880b198827",
            "name": "EventReport Test",
            "content": "This Event showcases a @[object](f91abf56-b017-462a-849f-d03ae0187498) MISP Object with its @[attribute](7ef43014-e2d6-4a13-b8fd-129fe4009310) value (also reported in a single attribute @[attribute](f9b286a9-3ed6-4ace-a60c-a5fe6529a783)) and the corresponding @[attribute](07a4c4aa-7380-44b5-82d4-06628ee3afba).\r\n\r\nThe event is also illustrated with the screenshot picturing the case we have here: @![attribute](f715be9f-845f-4d8c-8dce-852b353b3488)\r\n\r\n",
            "timestamp": "1603642920"
        }
    ]
}

_TEST_ATTACK_PATTERN_GALAXY = {
    "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
    "name": "Pre Attack - Attack Pattern",
    "type": "mitre-pre-attack-attack-pattern",
    "description": "ATT&CK Tactic",
    "GalaxyCluster": [
        {
            "uuid": "e042a41b-5ecf-4f3a-8f1f-1b528c534772",
            "type": "mitre-pre-attack-attack-pattern",
            "value": "Test malware in various execution environments - PRE-T1134",
            "description": "Malware may perform differently on different platforms and different operating systems.",
            "meta": {
                "external_id": "PRE-T1134",
                "kill_chain": [
                    "mitre-pre-attack:pre-attack:test-capabilities"
                ],
                "refs": [
                    "https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1134"
                ]
            }
        }
    ]
}

_TEST_COUNTRY_GALAXY = {
    "uuid": "84668357-5a8c-4bdd-9f0f-6b50b2aee4c1",
    "type": "country",
    "name": "Country",
    "description": "Country meta information",
    "GalaxyCluster": [
        {
            "uuid": "84668357-5a8c-4bdd-9f0f-6b50b2535745",
            "type": "country",
            "value": "sweden",
            "description": "Sweden",
            "meta": {
                "Capital": "Stockholm",
                "Continent": "EU",
                "CurrencyCode": "SEK",
                "CurrencyName": "Krona",
                "ISO": "SE",
                "ISO3": "SWE",
                "Languages": "sv-SE,se,sma,fi-SE",
                "Population": "9828655",
                "tld": ".se"
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
            "type": "mitre-course-of-action",
            "value": "Automated Exfiltration Mitigation - T1020",
            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
            "meta": {
                "external_id": "T1020",
                "refs": [
                    "http://technet.microsoft.com/en-us/magazine/2008.06.srp.aspx",
                    "http://www.sans.org/reading-room/whitepapers/application/application-whitelisting-panacea-propaganda-33599",
                    "https://apps.nsa.gov/iaarchive/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm",
                    "https://attack.mitre.org/mitigations/T1020",
                    "https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html",
                    "https://technet.microsoft.com/en-us/library/ee791851.aspx"
                ]
            }
        }
    ]
}

_TEST_INTRUSION_SET = {
    "uuid": "1023f364-7831-11e7-8318-43b5531983ab",
    "name": "Intrusion Set",
    "type": "mitre-intrusion-set",
    "description": "Name of ATT&CK Group",
    "GalaxyCluster": [
        {
            "uuid": "d6e88e18-81e8-4709-82d8-973095da1e70",
            "type": "mitre-intrusion-set",
            "value": "APT16 - G0023",
            "description": "APT16 is a China-based threat group that has launched spearphishing campaigns targeting Japanese and Taiwanese organizations.",
            "meta": {
                "external_id": "G0023",
                "refs": [
                    "https://attack.mitre.org/groups/G0023",
                    "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html"
                ],
                "synonyms": [
                    "APT16"
                ]
            }
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
            "type": "mitre-malware",
            "value": "BISCUIT - S0017",
            "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
            "meta": {
                "external_id": "S0017",
                "mitre_platforms": [
                    "Windows"
                ],
                "refs": [
                    "https://attack.mitre.org/software/S0017",
                    "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report-appendix.zip",
                    "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
                ],
                "synonyms": [
                    "BISCUIT"
                ]
            }
        }
    ]
}

_TEST_REGION_GALAXY = {
    "uuid": "d151a79a-e029-11e9-9409-f3e0cf3d93aa",
    "name": "Regions UN M49",
    "type": "region",
    "description": "Regions based on UN M49",
    "GalaxyCluster": [
        {
            "uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
            "type": "region",
            "value": "154 - Northern Europe",
            "description": "Nothern Europe",
            "meta": {
                "subregion": [
                    "830 - Channel Islands",
                    "248 - Åland Islands",
                    "208 - Denmark",
                    "233 - Estonia",
                    "234 - Faroe Islands",
                    "246 - Finland",
                    "352 - Iceland",
                    "372 - Ireland",
                    "833 - Isle of Man",
                    "428 - Latvia",
                    "440 - Lithuania",
                    "578 - Norway",
                    "744 - Svalbard and Jan Mayen Islands",
                    "752 - Sweden",
                    "826 - United Kingdom of Great Britain and Northern Ireland"
                ]
            }
        }
    ]
}

_TEST_SECTOR_GALAXY = {
    "uuid": "e1bb134c-ae4d-11e7-8aa9-f78a37325439",
    "name": "Sector",
    "type": "sector",
    "description": "Activity sectors",
    "GalaxyCluster": [
        {
            "uuid": "75597b7f-54e8-4f14-88c9-e81485ece483",
            "type": "sector",
            "value": "IT - Security"
        }
    ]
}

_TEST_TEA_MATRIX_GALAXY = {
    "uuid": "c5f2dfb4-21a1-42d8-a452-1d3c36a204ff",
    "name": "Tea Matrix",
    "type": "tea-matrix",
    "description": "Tea Matrix",
    "GalaxyCluster": [
        {
            "uuid": "24430dc6-9c27-4b3c-a5e7-6dda478fffa0",
            "type": "tea-matrix",
            "value": "Milk in tea",
            "description": "Milk in tea",
            "relationship_type": "ennemy-of"
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
            "type": "threat-actor",
            "value": "Cutting Kitten",
            "description": "These convincing profiles form a self-referenced network of seemingly established LinkedIn users.",
            "meta": {
                "cfr-type-of-incident": [
                    "Denial of service"
                ],
                "synonyms": [
                    "Ghambar"
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
            "type": "mitre-tool",
            "value": "cmd - S0106",
            "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
            "meta": {
                "external_id": "S0106",
                "mitre_platforms": [
                    "Windows"
                ],
                "refs": [
                    "https://attack.mitre.org/software/S0106",
                    "https://technet.microsoft.com/en-us/library/bb490880.aspx",
                    "https://technet.microsoft.com/en-us/library/bb490886.aspx",
                    "https://technet.microsoft.com/en-us/library/cc755121.aspx",
                    "https://technet.microsoft.com/en-us/library/cc771049.aspx"
                ],
                "synonyms": [
                    "cmd",
                    "cmd.exe"
                ]
            }
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
            "type": "branded-vulnerability",
            "value": "Ghost",
            "description": "The GHOST vulnerability is a serious weakness in the Linux glibc library.",
            "meta": {
                "aliases": [
                    "CVE-2015-0235"
                ]
            }
        }
    ]
}

_TEST_ACCOUNT_OBJECTS = [
    {
        "name": "gitlab-user",
        "description": "GitLab user. Gitlab.com user or self-hosted GitLab instance",
        "meta-category": "misc",
        "uuid": "20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "id",
                "value": "1234567890"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "John Doe"
            },
            {
                "type": "text",
                "object_relation": "username",
                "value": "j0hnd0e"
            }
        ]
    },
    {
        "name": "telegram-account",
        "description": "Information related to a telegram account",
        "meta-category": "misc",
        "uuid": "7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "id",
                "value": "1234567890"
            },
            {
                "type": "text",
                "object_relation": "username",
                "value": "T3l3gr4mUs3r"
            },
            {
                "type": "text",
                "object_relation": "phone",
                "value": "0112233445"
            },
            {
                "type": "text",
                "object_relation": "phone",
                "value": "0556677889"
            }
        ]
    }
]

_TEST_ACCOUNT_WITH_ATTACHMENT_OBJECTS = [
    {
        "name": "facebook-account",
        "description": "Facebook account.",
        "meta-category": "misc",
        "uuid": "7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "account-id",
                "value": "1392781243"
            },
            {
                "type": "text",
                "object_relation": "account-name",
                "value": "octocat"
            },
            {
                "type": "link",
                "object_relation": "link",
                "value": "https://facebook.com/octocat"
            },
            {
                "type": "attachment",
                "object_relation": "user-avatar",
                "value": "octocat.png"
            }
        ]
    },
    {
        "name": "github-user",
        "description": "GitHub user",
        "meta-category": "misc",
        "uuid": "5177abbd-c437-4acb-9173-eee371ad24da",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "id",
                "value": "1"
            },
            {
                "type": "github-username",
                "object_relation": "username",
                "value": "octocat"
            },
            {
                "type": "text",
                "object_relation": "user-fullname",
                "value": "Octo Cat"
            },
            {
                "type": "github-organisation",
                "object_relation": "organisation",
                "value": "GitHub"
            },
            {
                "type": "attachment",
                "object_relation": "profile-image",
                "value": "octocat.png"
            }
        ]
    },
    {
        "name": "parler-account",
        "description": "Parler account.",
        "meta-category": "misc",
        "uuid": "7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "account-id",
                "value": "42"
            },
            {
                "type": "text",
                "object_relation": "account-name",
                "value": "ParlerOctocat"
            },
            {
                "type": "boolean",
                "object_relation": "human",
                "value": False
            },
            {
                "type": "attachment",
                "object_relation": "profile-photo",
                "value": "octocat.png"
            }
        ]
    },
    {
        "name": "reddit-account",
        "description": "Reddit account.",
        "meta-category": "misc",
        "uuid": "43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "account-id",
                "value": "666"
            },
            {
                "type": "text",
                "object_relation": "account-name",
                "value": "RedditOctocat"
            },
            {
                "type": "text",
                "object_relation": "description",
                "value": "Reddit account of the OctoCat"
            },
            {
                "type": "attachment",
                "object_relation": "account-avatar",
                "value": "octocat.png"
            }
        ]
    },
    {
        "name": "twitter-account",
        "description": "Twitter account.",
        "meta-category": "misc",
        "uuid": "6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "id",
                "value": "1357111317"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "octocat"
            },
            {
                "type": "text",
                "object_relation": "displayed-name",
                "value": "Octo Cat"
            },
            {
                "type": "text",
                "object_relation": "followers",
                "value": "666"
            },
            {
                "type": "attachment",
                "object_relation": "profile-image",
                "value": "octocat.png"
            }
        ]
    }
]

_TEST_ASN_OBJECT = {
    "name": "asn",
    "meta-category": "network",
    "description": "Autonomous system object describing an autonomous system",
    "uuid": "5b23c82b-6508-4bdc-b580-045b0a00020f",
    "timestamp": "1603642920",
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
            "value": "1.2.3.4",
            "to_ids": False
        },
        {
            "type": "ip-src",
            "object_relation": "subnet-announced",
            "value": "8.8.8.8",
            "to_ids": False
        }
    ]
}

_TEST_ATTACK_PATTERN_OBJECT = {
    "name": "attack-pattern",
    "meta-category": "vulnerability",
    "description": "Attack pattern describing a common attack pattern enumeration and classification.",
    "uuid": "7205da54-70de-4fa7-9b34-e14e63fe6787",
    "timestamp": "1603642920",
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
        },
        {
            "type": "weakness",
            "object_relation": "related-weakness",
            "value": "CWE-118"
        },
        {
            "type": "weakness",
            "object_relation": "related-weakness",
            "value": "CWE-120"
        },
        {
            "type": "text",
            "object_relation": "prerequisites",
            "value": "The target hosst exposes a command-line utility to the user. The command-line utility exposed by the target host has a buffer overflow vulnerability that can be exploited."
        },
        {
            "type": "text",
            "object_relation": "solutions",
            "value": "Carefully review the service's implementation before making it available to users."
        }
    ]
}

_TEST_BANK_ACCOUNT_OBJECT = {
    "name": "bank-account",
    "meta-category": "financial",
    "description": "An object describing bank account information based on account description from goAML 4.0",
    "uuid": "695e7924-2518-4054-9cea-f82853d37410",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "8acaad62-227a-4988-96e7-4586847421a2",
            "type": "iban",
            "object_relation": "iban",
            "value": "LU1234567890ABCDEF1234567890",
            "to_ids": True
        },
        {
            "uuid": "c53382a1-cf4b-4901-a890-1611dbcc7101",
            "type": "bic",
            "object_relation": "swift",
            "value": "CTBKLUPP"
        },
        {
            "uuid": "c7c9f782-582f-4218-af79-e7901237e468",
            "type": "bank-account-nr",
            "object_relation": "account",
            "value": "1234567890"
        },
        {
            "uuid": "c206e7b4-7333-40a3-bf02-9647d32f9df2",
            "type": "text",
            "object_relation": "institution-name",
            "value": "Central Bank"
        },
        {
            "uuid": "f388d5e6-e4eb-401d-8ea4-efdd519659a1",
            "type": "text",
            "object_relation": "account-name",
            "value": "John Smith's bank account"
        },
        {
            "uuid": "c1ea07c0-a855-4c47-9df2-4acc0d3c4e63",
            "type": "text",
            "object_relation": "beneficiary",
            "value": "John Smith"
        },
        {
            "uuid": "5421d979-9af5-45ae-8c81-5005a4d7fc55",
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
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "b25b2538-36e3-4418-a42a-440eed163ffa",
            "type": "btc",
            "object_relation": "wallet-address",
            "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
            "to_ids": True
        },
        {
            "uuid": "dd142f6f-d8a0-4143-92b3-3b50e7cb1c51",
            "type": "float",
            "object_relation": "balance_BTC",
            "value": "2.25036953"
        },
        {
            "uuid": "7fd93652-5713-4390-bd15-94ec77e9c6d1",
            "type": "float",
            "object_relation": "BTC_received",
            "value": "3.35036953"
        },
        {
            "uuid": "c5c0532c-2a63-4f40-86a7-df27914a177e",
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
    "timestamp": "1603642920",
    "Attribute": [
        {
            "type": "text",
            "object_relation": "name",
            "value": "Block traffic to PIVY C2 Server (10.10.10.10)"
        },
        {
            "type": "text",
            "object_relation": "description",
            "value": "Block communication between the PIVY agents and the C2 Server"
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
    "timestamp": "1603642920",
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
    "timestamp": "1603642920",
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

_TEST_DOMAIN_IP_OBJECT_CUSTOM = {
    "name": "domain-ip",
    "meta-category": "network",
    "description": "A domain and IP address seen as a tuple",
    "uuid": "dc624447-684a-488f-9e16-f78f717d8efd",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "63fa4060-98d3-4768-b18d-cfbc52f2d0ff",
            "type": "domain",
            "object_relation": "domain",
            "value": "circl.lu"
        },
        {
            "uuid": "30e94901-9247-4d28-9746-ca4c0086201c",
            "type": "hostname",
            "object_relation": "hostname",
            "value": "circl.lu"
        },
        {
            "uuid": "fcbaf339-615a-409c-915f-034420dc90ca",
            "type": "ip-dst",
            "object_relation": "ip",
            "value": "149.13.33.14"
        },
        {
            "uuid": "ff192fba-c594-4eb2-8432-cd335ad6647d",
            "type": "port",
            "object_relation": "port",
            "value": "8443"
        }
    ]
}

_TEST_DOMAIN_IP_OBJECT_STANDARD = {
    "name": "domain-ip",
    "meta-category": "network",
    "description": "A domain and IP address seen as a tuple",
    "uuid": "5ac337df-e078-4e99-8b17-02550a00020f",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "a2e44443-a974-47b6-bb35-69d17b1cd243",
            "type": "domain",
            "object_relation": "domain",
            "value": "misp-project.org"
        },
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
        },
        {
            "uuid": "876133b5-b5fc-449c-ba9e-e467790da8eb",
            "type": "ip-dst",
            "object_relation": "ip",
            "value": "185.194.93.14"
        }
    ]
}

_TEST_EMAIL_OBJECT = {
    "name": "email",
    "meta-category": "network",
    "description": "Email object describing an email with meta-information",
    "uuid": "5e396622-2a54-4c8d-b61d-159da964451a",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "f5ec3603-e3d0-42d7-a372-14c1c137699b",
            "type": "email-src",
            "object_relation": "from",
            "value": "donald.duck@disney.com"
        },
        {
            "uuid": "3766d98d-d162-44d4-bc48-9518a2e48898",
            "type": "email-src-display-name",
            "object_relation": "from-display-name",
            "value": "Donald Duck"
        },
        {
            "uuid": "aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
            "type": "email-dst",
            "object_relation": "to",
            "value": "jdoe@random.org"
        },
        {
            "uuid": "3a93a3ef-fd04-4ce5-98f5-f53609b39b82",
            "type": "email-dst-display-name",
            "object_relation": "to-display-name",
            "value": "John Doe"
        },
        {
            "uuid": "1a43d189-e5f6-4087-98df-b2cbddec2cd6",
            "type": "email-dst",
            "object_relation": "cc",
            "value": "diana.prince@dc.us"
        },
        {
            "uuid": "59fc0279-427c-45a2-b8a4-678e43c6f9ad",
            "type": "email-dst-display-name",
            "object_relation": "cc-display-name",
            "value": "Diana Prince"
        },
        {
            "uuid": "efde9a0a-a62a-42a8-b863-14a448e313c6",
            "type": "email-dst",
            "object_relation": "cc",
            "value": "marie.curie@nobel.fr"
        },
        {
            "uuid": "bf64f806-1660-4790-8f07-b116eb41b9bc",
            "type": "email-dst-display-name",
            "object_relation": "cc-display-name",
            "value": "Marie Curie"
        },
        {
            "uuid": "3b940996-f99b-4bda-b065-69b8957f688c",
            "type": "email-dst",
            "object_relation": "bcc",
            "value": "jfk@gov.us"
        },
        {
            "uuid": "b824e555-8609-4389-9790-71e7f2785e1b",
            "type": "email-dst-display-name",
            "object_relation": "bcc-display-name",
            "value": "John Fitzgerald Kennedy"
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
        },
        {
            "uuid": "85d1fdf3-70d7-40b2-93a9-2ea2c8215fc6",
            "type": "email-message-id",
            "object_relation": "message-id",
            "value": "25"
        }
    ]
}

_TEST_EMAIL_OBJECT_WITH_DISPLAY_NAMES = {
    "name": "email",
    "meta-category": "network",
    "description": "Email object describing an email with meta-information",
    "uuid": "f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "f5ec3603-e3d0-42d7-a372-14c1c137699b",
            "type": "email-src",
            "object_relation": "from",
            "value": "donald.duck@disney.com"
        },
        {
            "uuid": "3766d98d-d162-44d4-bc48-9518a2e48898",
            "type": "email-src-display-name",
            "object_relation": "from-display-name",
            "value": "Donald Duck"
        },
        {
            "uuid": "aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
            "type": "email-dst",
            "object_relation": "to",
            "value": "jdoe@random.org"
        },
        {
            "uuid": "3a93a3ef-fd04-4ce5-98f5-f53609b39b82",
            "type": "email-dst-display-name",
            "object_relation": "to-display-name",
            "value": "John Doe"
        },
        {
            "uuid": "1a43d189-e5f6-4087-98df-b2cbddec2cd6",
            "type": "email-dst",
            "object_relation": "cc",
            "value": "diana.prince@dc.us"
        },
        {
            "uuid": "bf64f806-1660-4790-8f07-b116eb41b9bc",
            "type": "email-dst-display-name",
            "object_relation": "cc-display-name",
            "value": "Marie Curie"
        },
        {
            "uuid": "3b940996-f99b-4bda-b065-69b8957f688c",
            "type": "email-dst",
            "object_relation": "bcc",
            "value": "jfk@gov.us"
        },
        {
            "uuid": "b824e555-8609-4389-9790-71e7f2785e1b",
            "type": "email-dst-display-name",
            "object_relation": "bcc-display-name",
            "value": "John Fitzgerald Kennedy"
        }
    ]
}

_TEST_FILE_OBJECT = {
    "name": "file",
    "meta-category": "file",
    "description": "File object describing a file with meta-information",
    "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "malware-sample",
            "object_relation": "malware-sample",
            "value": "oui|8764605c6f388c89096b534d33565802",
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
            "value": "non"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "text",
            "object_relation": "path",
            "value": "/var/www/MISP/app/files/scripts/tmp"
        },
        {
            "type": "text",
            "object_relation": "file-encoding",
            "value": "UTF-8"
        },
        {
            "type": "datetime",
            "object_relation": "creation-time",
            "value": "2021-10-25T16:22:00Z"
        },
        {
            "type": "datetime",
            "object_relation": "modification-time",
            "value": "2022-10-25T16:22:00Z"
        }
    ]
}

_TEST_FILE_FOR_PE_OBJECT = {
    "name": "file",
    "meta-category": "file",
    "description": "File object describing a file with meta-information",
    "uuid": "5ac47782-e1b8-40b6-96b4-02510a00020f",
    "timestamp": "1603642920",
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

_TEST_GEOLOCATION_OBJECT = {
    "name": "geolocation",
    "meta-category": "misc",
    "description": "An object to describe a geographic location.",
    "uuid": "6a10dac8-71ac-4d9b-8269-1e9c73ea4d8f",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "type": "text",
            "object_relation": "address",
            "value": "9800 Savage Rd. Suite 6272"
        },
        {
            "type": "text",
            "object_relation": "zipcode",
            "value": "MD 20755"
        },
        {
            "type": "text",
            "object_relation": "city",
            "value": "Fort Meade"
        },
        {
            "type": "text",
            "object_relation": "country",
            "value": "USA"
        },
        {
            "type": "text",
            "object_relation": "countrycode",
            "value": "US"
        },
        {
            "type": "text",
            "object_relation": "region",
            "value": "northern-america"
        },
        {
            "type": "float",
            "object_relation": "latitude",
            "value": "39.108889"
        },
        {
            "type": "float",
            "object_relation": "longitude",
            "value": "-76.771389"
        },
        {
            "type": "float",
            "object_relation": "accuracy-radius",
            "value": "1"
        },
        {
            "type": "float",
            "object_relation": "altitude",
            "value": "55"
        }
    ]
}

_TEST_HTTP_REQUEST_OBJECT = {
    "name": "http-request",
    "meta-category": "network",
    "description": "A single HTTP request header",
    "uuid": "cfdb71ed-889f-4646-a388-43d936e1e3b9",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "8.8.8.8"
        },
        {
            "uuid": "d6f0e3b7-fa5d-4443-aea7-7b60b343bde7",
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "149.13.33.14"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "hostname",
            "object_relation": "host",
            "value": "circl.lu"
        },
        {
            "type": "http-method",
            "object_relation": "method",
            "value": "POST"
        },
        {
            "type": "user-agent",
            "object_relation": "user-agent",
            "value": "Mozilla Firefox"
        },
        {
            "type": "uri",
            "object_relation": "uri",
            "value": "/projects/internships/"
        },
        {
            "type": "url",
            "object_relation": "url",
            "value": "http://circl.lu/projects/internships/"
        },
        {
            "type": "text",
            "object_relation": "content-type",
            "value": "JSON"
        }
    ]
}

_TEST_IP_PORT_OBJECT = {
    "name": "ip-port",
    "meta-category": "network",
    "description": "An IP address (or domain) and a port",
    "uuid": "5ac47edc-31e4-4402-a7b6-040d0a00020f",
    "timestamp": "1603642920",
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
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "datetime",
            "object_relation": "first-seen",
            "value": "2020-10-25T16:22:00Z"
        }
    ]
}

_TEST_MUTEX_OBJECT = {
    "name": "mutex",
    "meta-category": "misc",
    "description": "Object to describe mutual exclusion locks (mutex) as seen in memory or computer program",
    "uuid": "b0f55591-6a63-4fbd-a169-064e64738d95",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "type": "text",
            "object_relation": "name",
            "value": "MutexTest"
        },
        {
            "type": "text",
            "object_relation": "description",
            "value": "Test mutex on unix"
        },
        {
            "type": "text",
            "object_relation": "operating-system",
            "value": "Unix"
        }
    ]
}

_TEST_NETFLOW_OBJECT = {
    "name": "netflow",
    "meta-category": "network",
    "description": "Netflow object describes an network object based on the Netflowv5/v9 minimal definition",
    "uuid": "419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "1.2.3.4"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "5.6.7.8"
        },
        {
            "uuid": "53a12da9-4b66-4809-b0b4-e9de3172e7a0",
            "type": "AS",
            "object_relation": "src-as",
            "value": "AS1234"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "AS",
            "object_relation": "dst-as",
            "value": "AS5678"
        },
        {
            "type": "port",
            "object_relation": "src-port",
            "value": "80"
        },
        {
            "type": "port",
            "object_relation": "dst-port",
            "value": "8080"
        },
        {
            "type": "text",
            "object_relation": "protocol",
            "value": "IP"
        },
        {
            "type": "datetime",
            "object_relation": "first-packet-seen",
            "value": "2020-10-25T16:22:00Z"
        },
        {
            "type": "text",
            "object_relation": "tcp-flags",
            "value": "00000002"
        }
    ]
}

_TEST_NETWORK_CONNECTION_OBJECT = {
    "name": "network-connection",
    "meta-category": "network",
    "description": "A local or remote network connection",
    "uuid": "5afacc53-c0b0-4825-a6ee-03c80a00020f",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "1.2.3.4"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "5.6.7.8"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "port",
            "object_relation": "src-port",
            "value": "8080"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "port",
            "object_relation": "dst-port",
            "value": "8080"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "hostname",
            "object_relation": "hostname-dst",
            "value": "circl.lu"
        },
        {
            "uuid": "e072dfbb-c6fd-4312-8201-d140575536c4",
            "type": "text",
            "object_relation": "layer3-protocol",
            "value": "IP"
        },
        {
            "uuid": "5acce519-b670-4cb2-af19-9c6d7b6f256c",
            "type": "text",
            "object_relation": "layer4-protocol",
            "value": "TCP"
        },
        {
            "uuid": "53a12da9-4b66-4809-b0b4-e9de3172e7a0",
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
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-src",
            "object_relation": "ip-src",
            "value": "1.2.3.4"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "object_relation": "ip-dst",
            "value": "5.6.7.8"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "port",
            "object_relation": "src-port",
            "value": "8080"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "port",
            "object_relation": "dst-port",
            "value": "8080"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "hostname",
            "object_relation": "hostname-dst",
            "value": "circl.lu"
        },
        {
            "uuid": "e072dfbb-c6fd-4312-8201-d140575536c4",
            "type": "text",
            "object_relation": "address-family",
            "value": "AF_INET"
        },
        {
            "uuid": "5acce519-b670-4cb2-af19-9c6d7b6f256c",
            "type": "text",
            "object_relation": "domain-family",
            "value": "PF_INET"
        },
        {
            "uuid": "a79ac2c8-c8c6-4a93-9f11-71a217ef3107",
            "type": "text",
            "object_relation": "socket-type",
            "value": "SOCK_RAW"
        },
        {
            "uuid": "53a12da9-4b66-4809-b0b4-e9de3172e7a0",
            "type": "text",
            "object_relation": "state",
            "value": "listening"
        },
        {
            "uuid": "2f057cc4-b70b-4305-9442-638dbb807a5c",
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
    "timestamp": "1603642920",
    "Attribute": [
        {
            "type": "text",
            "object_relation": "type",
            "value": "exe"
        },
        {
            "type": "datetime",
            "object_relation": "compilation-timestamp",
            "value": "2019-03-16T12:31:22Z"
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
    "timestamp": "1603642920",
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
            "value": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK",
        }
    ]
}

_TEST_PERSON_OBJECT = {
    "name": "person",
    "meta-category": "misc",
    "description": "An object which describes a person or an identity.",
    "uuid": "868037d5-d804-4f1d-8016-f296361f9c68",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "37c42710-aaf7-4f10-956b-f8eb7adffb81",
            "type": "first-name",
            "object_relation": "first-name",
            "value": "John"
        },
        {
            "uuid": "05583483-4d7f-496a-aa1b-279d484b5966",
            "type": "last-name",
            "object_relation": "last-name",
            "value": "Smith"
        },
        {
            "uuid": "a4e174fc-f341-432f-beb3-27b99ec22541",
            "type": "nationality",
            "object_relation": "nationality",
            "value": "USA"
        },
        {
            "uuid": "f6f12b78-5f96-4c64-9462-2e881d70cd4a",
            "type": "passport-number",
            "object_relation": "passport-number",
            "value": "ABA9875413"
        },
        {
            "uuid": "6c0a87f4-54a3-401a-a37f-13b2996d4d37",
            "type": "phone-number",
            "object_relation": "phone-number",
            "value": "0123456789"
        },
        {
            "uuid": "6a464f2f-1ae0-4810-ab67-378e2489b8c0",
            "type": "text",
            "object_relation": "role",
            "value": "Guru"
        }
    ]
}

_TEST_PROCESS_OBJECT = {
    "name": "process",
    "meta-category": "misc",
    "description": "Object describing a system process.",
    "uuid": "5e39776a-b284-40b3-8079-22fea964451a",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "text",
            "object_relation": "pid",
            "value": "2510"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "text",
            "object_relation": "child-pid",
            "value": "1401"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "text",
            "object_relation": "parent-pid",
            "value": "2107"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "text",
            "object_relation": "name",
            "value": "TestProcess"
        },
        {
            "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
            "type": "filename",
            "object_relation": "image",
            "value": "test_process.exe"
        },
        {
            "uuid": "d01ef2c6-3154-4f8a-a3dc-9de1f34dd5d0",
            "type": "filename",
            "object_relation": "parent-image",
            "value": "parent_process.exe"
        },
        {
            "uuid": "e072dfbb-c6fd-4312-8201-d140575536c4",
            "type": "port",
            "object_relation": "port",
            "value": "1234"
        },
        {
            "type": "boolean",
            "object_relation": "hidden",
            "value": "True"
        }
    ]
}

_TEST_REGISTRY_KEY_OBJECT = {
    "name": "registry-key",
    "meta-category": "file",
    "description": "Registry key object describing a Windows registry key",
    "uuid": "5ac3379c-3e74-44ba-9160-04120a00020f",
    "timestamp": "1603642920",
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
            "value": "%DATA%\\qwertyuiop"
        },
        {
            "type": "text",
            "object_relation": "data-type",
            "value": "REG_SZ"
        },
        {
            "type": "datetime",
            "object_relation": "last-modified",
            "value": "2020-10-25T16:22:00Z"
        }
    ]
}

_TEST_REPORT_OBJECT = {
    "uuid": "3e76898a-fcb1-485b-ac24-d450fe8c54bc",
    "name": "report",
    "meta-category": "misc",
    "description": "Metadata used to generate an executive level report",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "uuid": "11798cf8-1f53-448d-b424-e0bd7402492c",
            "type": "text",
            "object_relation": "summary",
            "value": "It is compromised"
        },
        {
            "uuid": "84a5575e-bbe4-4a55-a75d-c4a91b0d1e23",
            "type": "text",
            "object_relation": "type",
            "value": "Report"
        },
        {
            "uuid": "5742717c-7689-4440-af20-3cb44edb45cf",
            "type": "attachment",
            "object_relation": "report-file(s)",
            "value": "report.md",
            "data": "VGhyZWF0IFJlcG9ydAoKSXQgaXMgY29tcHJvbWlzZWQK"
        }
    ]
}

_TEST_SCRIPT_OBJECT = {
    "name": "script",
    "meta-category": "misc",
    "description": "Object describing a computer program written to be run in a special run-time environment.",
    "timestamp": "1603642920",
    "Attribute": [
        {
            "type": "text",
            "object_relation": "language",
            "value": "Python"
        }
    ]
}

_TEST_SIGHTINGS = [
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "AS",
        "category": "Network activity",
        "timestamp": "1603642920",
        "value": "AS174",
        "Sighting": [
            {
                "uuid": "5125aa81-ab95-4cdf-83f9-3c467207307d",
                "date_sighting": "1603642925",
                "type": "0",
                "Organisation": {
                    "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f",
                    "name": "CIRCL"
                }
            },
            {
                "uuid": "b5b53917-1556-4476-97eb-52e179e3393e",
                "date_sighting": "1603642950",
                "type": "0",
                "Organisation": {
                    "uuid": "7b9774b7-528b-4b03-bbb8-a0dd9e546183",
                    "name": "E-Corp"
                }
            },
            {
                "uuid": "ec85cc8c-205f-4b19-8f96-73ef80d24d13",
                "date_sighting": "1603642930",
                "type": "1",
                "Organisation": {
                    "uuid": "93d5d857-822c-4c53-ae81-a05ffcbd2a90",
                    "name": "Oscorp Industries"
                }
            },
            {
                "uuid": "7ea813e5-6dd5-4241-83a7-37fb56da2d78",
                "date_sighting": "1603642940",
                "type": "1",
                "Organisation": {
                    "uuid": "91050751-c1c9-4944-a522-db6390cec15b",
                    "name": "Umbrella Corporation"
                }
            }
        ]
    },
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "domain",
        "category": "Network activity",
        "value": "circl.lu",
        "timestamp": "1603642920",
        "comment": "Domain test attribute",
        "to_ids": True,
        "Sighting": [
            {
                "uuid": "5533d0db-b952-4609-b82d-59017f2454fc",
                "date_sighting": "1603642925",
                "type": "0",
                "Organisation": {
                    "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f",
                    "name": "CIRCL"
                }
            },
            {
                "uuid": "c7d12059-6a07-4423-a82a-f3bceaae33c8",
                "date_sighting": "1603642950",
                "type": "1",
                "Organisation": {
                    "uuid": "7b9774b7-528b-4b03-bbb8-a0dd9e546183",
                    "name": "E-Corp"
                }
            },
            {
                "uuid": "ec0c6809-9ccb-4201-bc47-d5ffc5ecaa88",
                "date_sighting": "1603642940",
                "type": "0",
                "Organisation": {
                    "uuid": "93d5d857-822c-4c53-ae81-a05ffcbd2a90",
                    "name": "Oscorp Industries"
                }
            },
            {
                "uuid": "3ab7497e-39f5-4a0a-b797-dc08bf80631d",
                "date_sighting": "1603642930",
                "type": "1",
                "Organisation": {
                    "uuid": "91050751-c1c9-4944-a522-db6390cec15b",
                    "name": "Umbrella Corporation"
                }
            }
        ]
    }
]

_TEST_URL_OBJECT = {
    "name": "url",
    "meta-category": "network",
    "description": "url object describes an url along with its normalized field",
    "uuid": "5ac347ca-dac4-4562-9775-04120a00020f",
    "timestamp": "1603642920",
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
    "timestamp": "1603642920",
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
        {
            "type": "attachment",
            "object_relation": "user-avatar",
            "value": "octocat.png"
        }
    ]
}

_TEST_VULNERABILITY_OBJECT = {
    "name": "vulnerability",
    "meta-category": "vulnerability",
    "description": "Vulnerability object describing a common vulnerability",
    "uuid": "5e579975-e9cc-46c6-a6ad-1611a964451a",
    "timestamp": "1603642920",
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
            "value": "2017-10-13T07:29:00Z"
        },
        {
            "type": "datetime",
            "object_relation": "published",
            "value": "2017-10-13T07:29:00Z"
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
    "timestamp": "1603642920",
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

_TEST_WHOIS_OBJECT = {
    "name": "whois",
    "meta-category": "network",
    "description": "Whois records information for a domain name or an IP address.",
    "uuid": "5b0d1b61-6c00-4387-a5fa-04370a00020f",
    "timestamp": "1603642920",
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
            "value": "2017-10-01T08:00:00Z"
        },
        {
            "type": "datetime",
            "object_relation": "modification-date",
            "value": "2020-10-25T16:22:00Z"
        },
        {
            "type": "datetime",
            "object_relation": "expiration-date",
            "value": "2021-01-01T00:00:00Z"
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

_TEST_X509_OBJECT = {
    "name": "x509",
    "meta-category": "network",
    "description": "x509 object describing a X.509 certificate",
    "uuid": "5ac3444e-145c-4749-8467-02550a00020f",
    "timestamp": "1603642920",
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
            "object_relation": "signature_algorithm",
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
            "value": "2020-01-01T00:00:00Z"
        },
        {
            "type": "datetime",
            "object_relation": "validity-not-after",
            "value": "2021-01-01T00:00:00Z"
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

_CAMPAIGN_NAME_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "campaign-name",
    "category": "Attribution",
    "value": "MartyMcFly",
    "timestamp": "1603642920",
    "to_ids": False
}

_INDICATOR_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "domain",
    "category": "Network activity",
    "value": "circl.lu",
    "timestamp": "1603642920",
    "comment": "Domain test attribute",
    "to_ids": True
}

_NON_INDICATOR_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "vulnerability",
    "category": "External analysis",
    "value": "CVE-2017-11774",
    "timestamp": "1603642920",
    "comment": "Vulnerability test attribute"
}

_OBSERVABLE_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "AS",
    "category": "Network activity",
    "timestamp": "1603642920",
    "value": "AS174"
}

################################################################################
#                               BASE EVENT TESTS                               #
################################################################################

def get_base_event():
    return deepcopy(_BASE_EVENT)


def get_event_with_attribute_confidence_tags():
    tags = [
        {'name': 'tlp:white'},
        {"name": 'misp:confidence-level="completely-confident"'},
        {"name": 'misp:confidence-level="fairly-confident"'}
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Tag'] = deepcopy(tags)
    attributes = [
        deepcopy(_INDICATOR_ATTRIBUTE),
        deepcopy(_CAMPAIGN_NAME_ATTRIBUTE),
        deepcopy(_NON_INDICATOR_ATTRIBUTE),
        deepcopy(_OBSERVABLE_ATTRIBUTE)
    ]
    for attribute in attributes:
        attribute['Tag'] = deepcopy(tags)
    event['Event']['Attribute'] = attributes
    return event


def get_event_with_escaped_values_v20():
    event = deepcopy(_EVENT_FOR_ESCAPING_TESTS)
    with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
        event['Event']['Attribute'][22]['data'] = b64encode(f.read()).decode()
    return event


def get_event_with_escaped_values_v21():
    event = deepcopy(_EVENT_FOR_ESCAPING_TESTS)
    with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
        event['Event']['Attribute'][22]['data'] = b64encode(f.read()).decode()
    event['Event']['Attribute'].append(
        {
            "uuid": "f3745b11-2b82-4798-80ba-d32c506135ec",
            "type": "email-message-id",
            "category": "Payload delivery",
            "value": "'1234'",
            "timestamp": "1603642920",
            "to_ids": True
        }
    )
    return event


def get_event_with_object_confidence_tags():
    tags = [
        {'name': 'tlp:white'},
        {'name': 'misp:confidence-level="confidence-cannot-be-evaluated"'},
        {'name': 'misp:confidence-level="usually-confident"'}
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Tag'] = deepcopy(tags)
    ip_port_object = deepcopy(_TEST_IP_PORT_OBJECT)
    ip_port_object['Attribute'][0]['to_ids'] = True
    misp_objects = [
        ip_port_object,
        deepcopy(_TEST_COURSE_OF_ACTION_OBJECT),
        deepcopy(_TEST_ASN_OBJECT)
    ]
    for misp_object in misp_objects:
        for attribute, tag in zip(misp_object['Attribute'][:3], tags):
            attribute['Tag'] = [tag]
    event['Event']['Object'] = misp_objects
    return event


def get_event_with_tags():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Tag'] = [
        {"name": "tlp:white"},
        {"name": 'misp:tool="misp2stix"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Code Signing - T1116"'},
        {"name": 'misp-galaxy:mitre-pre-attack-attack-pattern="Test malware in various execution environments - PRE-T1134"'}
    ]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY)
    ]
    return event


def get_published_event():
    base_event = deepcopy(_BASE_EVENT)
    base_event['Event']['date'] = '2020-10-25'
    base_event['Event']['timestamp'] = '1603642920'
    base_event['Event']['published'] = True
    base_event['Event']['publish_timestamp'] = "1603642920"
    return base_event


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


def get_event_with_custom_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_TEA_MATRIX_GALAXY)
    ]
    return event


def get_event_with_intrusion_set_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_INTRUSION_SET)
    ]
    return event


def get_event_with_location_galaxies():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_COUNTRY_GALAXY),
        deepcopy(_TEST_REGION_GALAXY)
    ]
    return event


def get_event_with_malware_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE_GALAXY)
    ]
    return event


def get_event_with_sector_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_SECTOR_GALAXY)
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

_BTC_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "btc",
    "category": "Financial fraud",
    "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
    "timestamp": "1603642920",
    "comment": "Btc test attribute",
    "to_ids": True
}

_EMAIL_DESTINATION_ATTRIBUTE = {
    "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
    "type": "email-dst",
    "category": "Payload delivery",
    "value": "dst@email.test",
    "timestamp": "1603642920",
    "comment": "Destination email address test attribute",
    "to_ids": True
}

_EMAIL_MESSAGE_ID_ATTRIBUTE = {
    "uuid": "f3745b11-2b82-4798-80ba-d32c506135ec",
    "type": "email-message-id",
    "category": "Payload delivery",
    "value": "1234",
    "timestamp": "1603642920"
}

_EMAIL_REPLY_TO_ATTRIBUTE = {
    "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
    "type": "email-reply-to",
    "category": "Payload delivery",
    "value": "reply-to@email.test",
    "timestamp": "1603642920"
}

_EMAIL_SOURCE_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "email-src",
    "category": "Payload delivery",
    "value": "src@email.test",
    "timestamp": "1603642920",
    "comment": "Source email address test attribute",
    "to_ids": True
}

_EMAIL_SUBJECT_ATTRIBUTE = {
    "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
    "type": "email-subject",
    "category": "Payload delivery",
    "value": "Test Subject",
    "timestamp": "1603642920"
}

_EMAIL_X_MAILER_ATTRIBUTE = {
    "uuid": "f09d8496-e2ba-4250-878a-bec9b85c7e96",
    "type": "email-x-mailer",
    "category": "Payload delivery",
    "value": "Email X-Mailer test",
    "timestamp": "1603642920"
}

_HTTP_METHOD_ATTRIBUTE = {
    "uuid": "d94bdd2c-3603-4044-8b70-20090e7526ad",
    "type": "http-method",
    "category": "Network activity",
    "value": "POST",
    "timestamp": "1603642920",
    "to_ids": False
}

_IBAN_ATTRIBUTE = {
    "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
    "type": "iban",
    "category": "Financial fraud",
    "value": "LU1234567890ABCDEF1234567890",
    "timestamp": "1603642920",
    "comment": "IBAN test attribute",
    "to_ids": True
}

_PORT_ATTRIBUTE = {
    "uuid": "1af096a0-efa1-4331-9300-a6b5eb4df2e6",
    "type": "port",
    "category": "Network activity",
    "value": "8443",
    "timestamp": "1603642920",
    "to_ids": False
}

_SIZE_IN_BYTES_ATTRIBUTE = {
    "uuid": "8be8065b-ca71-4210-976e-2804665a502d",
    "type": "size-in-bytes",
    "value": "1234",
    "category": "Other",
    "timestamp": "1603642920",
    "to_ids": False
}

_USER_AGENT_ATTRIBUTE = {
    "uuid": "f0b5b638-81b4-4509-bd40-1e114955caf4",
    "type": "user-agent",
    "category": "Network activity",
    "value": "Mozilla Firefox",
    "timestamp": "1603642920",
    "comment": "User-agent test attribute",
    "to_ids": False
}


def get_indicator_attribute_with_galaxy():
    attribute = deepcopy(_INDICATOR_ATTRIBUTE)
    attribute['Galaxy'] = [
        deepcopy(_TEST_ATTACK_PATTERN_GALAXY),
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY)
    ]
    return attribute


def get_embedded_indicator_attribute_galaxy():
    attribute = get_indicator_attribute_with_galaxy()
    attribute['Galaxy'].append(deepcopy(_TEST_TEA_MATRIX_GALAXY))
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [attribute]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_MALWARE_GALAXY),
        deepcopy(_TEST_TEA_MATRIX_GALAXY)
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
            "data": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK",
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_campaign_name_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_CAMPAIGN_NAME_ATTRIBUTE)
    ]
    return event


def get_event_with_stix1_custom_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_BTC_ATTRIBUTE),
        deepcopy(_IBAN_ATTRIBUTE),
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


def get_event_with_stix2_custom_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_BTC_ATTRIBUTE),
        deepcopy(_IBAN_ATTRIBUTE),
        deepcopy(_HTTP_METHOD_ATTRIBUTE),
        deepcopy(_PORT_ATTRIBUTE),
        deepcopy(_SIZE_IN_BYTES_ATTRIBUTE),
        deepcopy(_USER_AGENT_ATTRIBUTE)
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
            "timestamp": "1603642920",
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
            "timestamp": "1603642920",
            "comment": "Email attachment test attribute",
            "to_ids": True
        }
    ]
    return event


def get_event_with_email_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_SOURCE_ATTRIBUTE),
        deepcopy(_EMAIL_DESTINATION_ATTRIBUTE),
        deepcopy(_EMAIL_SUBJECT_ATTRIBUTE),
        deepcopy(_EMAIL_REPLY_TO_ATTRIBUTE),
        deepcopy(_EMAIL_MESSAGE_ID_ATTRIBUTE),
        deepcopy(_EMAIL_X_MAILER_ATTRIBUTE),
        {
            "uuid": "30c728ce-4ee4-4dc4-b7f6-ae4e900f4aa9",
            "type": "email-mime-boundary",
            "category": "Payload delivery",
            "value": "----=_NextPart_001_1F9B_01D27892.CB6A37E0",
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_email_address_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email",
            "category": "Payload delivery",
            "value": "address@email.test",
            "timestamp": "1603642920",
            'to_ids': True
        }
    ]
    return event


def get_event_with_email_body_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email-body",
            "category": "Payload delivery",
            "value": "Email body test",
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_email_destination_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_DESTINATION_ATTRIBUTE)
    ]
    return event


def get_event_with_email_header_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "email-header",
            "category": "Payload delivery",
            "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com",
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_email_message_id_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_MESSAGE_ID_ATTRIBUTE)
    ]
    return event


def get_event_with_email_reply_to_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_REPLY_TO_ATTRIBUTE)
    ]
    return event


def get_event_with_email_source_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_SOURCE_ATTRIBUTE)
    ]
    return event


def get_event_with_email_x_mailer_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_X_MAILER_ATTRIBUTE)
    ]
    return event


def get_event_with_email_subject_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_EMAIL_SUBJECT_ATTRIBUTE)
    ]
    return event


def get_event_with_event_report():
    event = deepcopy(_BASE_EVENT)
    event['Event'].update(deepcopy(_TEST_EVENT_REPORT))
    with open(_TESTFILES_PATH / 'google_screenshot.png', 'rb') as f:
        event['Event']['Attribute'][-1]['data'] = b64encode(f.read()).decode()
    return event


def get_event_with_filename_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "filename",
            "category": "Payload delivery",
            "value": "test_file_name",
            "timestamp": "1603642920",
            "comment": "Filename test attribute",
            "to_ids": True
        }
    ]
    return event


def get_event_with_github_username_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "github-username",
            "category": "Social network",
            "value": "chrisr3d",
            "timestamp": "1603642920",
            "comment": "Github username test attribute"
        }
    ]
    return event


def get_event_with_hash_attributes(to_ids=True):
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = list(
        _get_hash_attributes(to_ids)
    )
    event['Event']['Attribute'].append(
        {
            "uuid": "4846cade-2492-4e7d-856e-2afcd282455b",
            "type": "telfhash",
            "category": "Payload delivery",
            "timestamp": "1603642920",
            "value": "b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b",
            "comment": "TELFHASH test attribute",
            "to_ids": True
        }
    )
    return event


def get_event_with_hash_composite_attributes(to_ids=True):
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = list(
        _get_hash_composite_attributes(to_ids)
    )
    return event


def get_event_with_hostname_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "hostname",
            "category": "Network activity",
            "value": "circl.lu",
            "timestamp": "1603642920",
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
            "timestamp": "1603642920",
            "comment": "Hostname|port test attribute",
            "to_ids": True
        }
    ]
    return event


def get_event_with_http_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_HTTP_METHOD_ATTRIBUTE),
        deepcopy(_USER_AGENT_ATTRIBUTE)
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
            "timestamp": "1603642920",
            "comment": "Source IP test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst",
            "category": "Network activity",
            "value": "5.6.7.8",
            "to_ids": True,
            "timestamp": "1603642920",
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
            "timestamp": "1603642920",
            "comment": "Source IP | Port test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "ip-dst|port",
            "category": "Network activity",
            "value": "5.6.7.8|5678",
            "to_ids": True,
            "timestamp": "1603642920",
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
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_malware_sample_attribute():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
        event['Event']['Attribute'] = [
            {
                "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "type": "malware-sample",
                "category": "Payload delivery",
                "value": "oui|8764605c6f388c89096b534d33565802",
                "data": b64encode(f.read()).decode(),
                "to_ids": True,
                "timestamp": "1603642920",
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
            "timestamp": "1603642920",
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
            "timestamp": "1603642920",
            "comment": "Named pipe test attribute"
        }
    ]
    return event


def get_event_with_patterning_language_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "sigma",
            "category": "Artifacts dropped",
            "value": "title: Ps.exe Renamed SysInternals Tool description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A report reference: https://www.us-cert.gov/ncas/alerts/TA17-293A author: Florian Roth date: 2017/10/22 logsource: product: windows service: sysmon detection: selection: EventID: 1 CommandLine: 'ps.exe -accepteula' condition: selection falsepositives: - Renamed SysInternals tool level: high",
            "timestamp": "1603642920",
            "comment": "Sigma test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "snort",
            "category": "Network activity",
            "value": "alert http any 443 -> 8.8.8.8 any",
            "timestamp": "1603642920",
            "comment": "Snort test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "yara",
            "category": "Payload installation",
            "value": 'rule torcryptomining { meta: description = "Tor miner - broken UPX magic string" strings: $upx_erase = {(00 FF 99 41|DF DD 30 33)} condition: $upx_erase at 236 }',
            "timestamp": "1603642920",
            "comment": "Yara test attribute"
        }
    ]
    return event


def get_event_with_port_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_PORT_ATTRIBUTE)
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
            "timestamp": "1603642920",
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
            "value": "HKLM\Software\mthjk|%DATA%\\1234567890",
            "to_ids": True,
            "timestamp": "1603642920",
            "comment": "Regkey | value test attribute"
        }
    ]
    return event


def get_event_with_sightings():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = deepcopy(_TEST_SIGHTINGS)
    return event


def get_event_with_size_in_bytes_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        deepcopy(_SIZE_IN_BYTES_ATTRIBUTE)
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
            "timestamp": "1603642920",
            "comment": "Snort test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "yara",
            "category": "Payload installation",
            "value": 'import "pe" rule single_section{condition:pe.number_of_sections == 1}',
            "to_ids": True,
            "timestamp": "1603642920",
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


def get_event_with_url_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "link",
            "category": "External analysis",
            "value": "https://misp-project.org/download/",
            "to_ids": True,
            "timestamp": "1603642920",
            "comment": "Link test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "uri",
            "category": "Network activity",
            "value": "https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova",
            "to_ids": True,
            "timestamp": "1603642920",
            "comment": "URI test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "url",
            "category": "Network activity",
            "value": "https://vm.misp-project.org/latest/",
            "to_ids": True,
            "timestamp": "1603642920",
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
            "timestamp": "1603642920",
            "comment": "Weakness test attribute"
        }
    ]
    return event


def get_event_with_whois_registrar_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "whois-registrar",
            "category": "Attribution",
            "value": "Registrar.eu"
        }
    ]
    return event


def get_event_with_whois_registrant_attributes():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "whois-registrant-email",
            "category": "Attribution",
            "value": "registrant@email.org"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "whois-registrant-name",
            "category": "Attribution",
            "value": "Registrant Name"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "whois-registrant-org",
            "category": "Attribution",
            "value": "Registrant Org"
        },
        {
            "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
            "type": "whois-registrant-phone",
            "category": "Attribution",
            "value": "0123456789"
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
            "timestamp": "1603642920",
            "comment": "X509 MD5 fingerprint test attribute"
        },
        {
            "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
            "type": "x509-fingerprint-sha1",
            "category": "Payload delivery",
            "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
            "to_ids": True,
            "timestamp": "1603642920",
            "comment": "X509 SHA1 fingerprint test attribute"
        },
        {
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "type": "x509-fingerprint-sha256",
            "category": "Payload delivery",
            "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
            "to_ids": True,
            "timestamp": "1603642920",
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
    misp_object['Attribute'][2]['Galaxy'] = [deepcopy(_TEST_TEA_MATRIX_GALAXY)]
    event['Event']['Object'] = [misp_object]
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_TOOL_GALAXY),
        deepcopy(_TEST_COURSE_OF_ACTION_GALAXY),
        deepcopy(_TEST_TEA_MATRIX_GALAXY)
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
                    "type": "mitre-malware",
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


def get_event_with_account_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = deepcopy(_TEST_ACCOUNT_OBJECTS)
    return event


def get_event_with_account_objects_with_attachment():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = deepcopy(_TEST_ACCOUNT_WITH_ATTACHMENT_OBJECTS)
    with open(_TESTFILES_PATH / 'octocat.png', 'rb') as f:
        data = b64encode(f.read()).decode()
    for misp_object in event['Event']['Object']:
        misp_object['Attribute'][-1]['data'] = data
    return event


def get_event_with_android_app_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "android-app",
            "description": "Indicators related to an Android app",
            "meta-category": "file",
            "uuid": "02782ed5-b27f-4abc-8bae-efebe13a46dd",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name",
                    "value": "Facebook"
                },
                {
                    "type": "sha1",
                    "object_relation": "certificate",
                    "value": "c3a94cdf5ad4d71fd60c16ba8801529c78e7398f"
                },
                {
                    "type": "domain",
                    "object_relation": "domain",
                    "value": "facebook.com"
                }
            ]
        }
    ]
    return event


def get_event_with_annotation_object():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'annotation.attachment', 'rb') as f:
        event['Event']['Object'] = [
            {
                "name": "annotation",
                "description": "An annotation object allowing analysts to add annotations, comments, executive summary to a MISP event, objects or attributes.",
                "meta-category": "misc",
                "uuid": "eb6592bb-675c-48f3-9272-157141196b93",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "text",
                        "value": "Google public DNS"
                    },
                    {
                        "type": "text",
                        "object_relation": "type",
                        "value": "Executive Summary"
                    },
                    {
                        "type": "attachment",
                        "object_relation": "attachment",
                        "value": "annotation.attachment",
                        "data": b64encode(f.read()).decode()
                    }
                ],
                "ObjectReference": [
                    {
                        "referenced_uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "relationship_type": "annotates"
                    }
                ]
            }
        ]
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "ip-dst",
            "category": "Network activity",
            "value": "8.8.8.8",
            "to_ids": True,
            "timestamp": "1603642920"
        }
    ]
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


def get_event_with_cpe_asset_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "cpe-asset",
            "description": "An asset which can be defined by a CPE.",
            "meta-category": "misc",
            "uuid": "3f53a829-6307-4006-b7a2-ff53dace4159",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "cpe",
                    "object_relation": "cpe",
                    "value": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*"
                },
                {
                    "type": "text",
                    "object_relation": "language",
                    "value": "ENG"
                },
                {
                    "type": "text",
                    "object_relation": "product",
                    "value": "Word"
                },
                {
                    "type": "text",
                    "object_relation": "vendor",
                    "value": "Microsoft"
                },
                {
                    "type": "text",
                    "object_relation": "version",
                    "value": "2002"
                },
                {
                    "type": "text",
                    "object_relation": "description",
                    "value": "Microsoft Word is a word processing software developed by Microsoft."
                }
            ]
        }
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
        deepcopy(_TEST_REPORT_OBJECT)
    ]
    return event


def get_event_with_domain_ip_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_DOMAIN_IP_OBJECT)
    ]
    return event


def get_event_with_domain_ip_object_custom():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_DOMAIN_IP_OBJECT_CUSTOM)
    ]
    return event


def get_event_with_domain_ip_object_standard():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_DOMAIN_IP_OBJECT_STANDARD)
    ]
    return event


def get_event_with_email_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_EMAIL_OBJECT)
    ]
    return event


def get_event_with_email_object_with_display_names():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_EMAIL_OBJECT_WITH_DISPLAY_NAMES)
    ]
    return event


def get_event_with_employee_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "employee",
            "description": "An employee and related data points",
            "meta-category": "misc",
            "uuid": "685a38e1-3ca1-40ef-874d-3a04b9fb3af6",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "first-name",
                    "object_relation": "first-name",
                    "value": "John"
                },
                {
                    "type": "last-name",
                    "object_relation": "last-name",
                    "value": "Doe"
                },
                {
                    "type": "text",
                    "object_relation": "text",
                    "value": "John Doe is known"
                },
                {
                    "type": "target-email",
                    "object_relation": "email-address",
                    "value": "jdoe@email.com"
                },
                {
                    "type": "text",
                    "object_relation": "employee-type",
                    "value": "Supervisor"
                }
            ]
        }
    ]
    return event


def get_event_with_file_object_with_artifact():
    event = deepcopy(_BASE_EVENT)
    file_object = deepcopy(_TEST_FILE_OBJECT)
    with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
        file_object['Attribute'][0]['data'] = b64encode(f.read()).decode()
    file_object['Attribute'][6]['data'] = "Tm9uLW1hbGljaW91cyBmaWxlCg=="
    event['Event']['Object'] = [
        file_object
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
    event['Event']['Object'] = [
        deepcopy(_TEST_FILE_OBJECT)
    ]
    return event


def get_event_with_geolocation_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_GEOLOCATION_OBJECT)
    ]
    return event


def get_event_with_http_request_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_HTTP_REQUEST_OBJECT)
    ]
    return event


def get_event_with_identity_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "identity",
            "description": "Identities can represent actual individuals, organizations, or groups as well as classes of individuals, organizations, systems or groups.",
            "meta-category": "misc",
            "uuid": "a54e32af-5569-4949-b1fe-ad75054cde45",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name",
                    "value": "John Doe"
                },
                {
                    "type": "text",
                    "object_relation": "contact_information",
                    "value": "email-address: jdoe@email.com / phone-number: 0123456789"
                },
                {
                    "type": "text",
                    "object_relation": "description",
                    "value": "Unknown person"
                },
                {
                    "type": "text",
                    "object_relation": "identity_class",
                    "value": "individual"
                },
                {
                    "type": "text",
                    "object_relation": "roles",
                    "value": "Placeholder name"
                }
            ]
        }
    ]
    return event


def get_event_with_image_object():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'STIX_logo.png', 'rb') as f:
        event['Event']['Object'] = [
            {
                "name": "image",
                "description": "Object describing an image file.",
                "meta-category": "file",
                "uuid": "939b2f03-c487-4f62-a90e-cab7acfee294",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "attachment",
                        "object_relation": "attachment",
                        "value": "STIX.png",
                        "data": b64encode(f.read()).decode()
                    },
                    {
                        "type": "filename",
                        "object_relation": "filename",
                        "value": "STIX.png"
                    },
                    {
                        "uuid": "d85eeb1a-f4a2-4b9f-a367-d84f9a7e6303",
                        "type": "url",
                        "object_relation": "url",
                        "value": "https://oasis-open.github.io/cti-documentation/img/STIX.png"
                    },
                    {
                        "type": "text",
                        "object_relation": "image-text",
                        "value": "STIX"
                    }
                ]
            }
        ]
    return event


def get_event_with_ip_port_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_IP_PORT_OBJECT)
    ]
    return event


def get_event_with_legal_entity_object():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'umbrella_logo.png', 'rb') as f:
        event['Event']['Object'] = [
            {
                "name": "legal-entity",
                "description": "An object to describe a legal entity.",
                "meta-category": "misc",
                "uuid": "0d55ba1f-c3ff-4b91-8a09-8713576e178b",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "name",
                        "value": "Umbrella Corporation"
                    },
                    {
                        "type": "text",
                        "object_relation": "text",
                        "value": "The Umbrella Corporation is an international pharmaceutical company."
                    },
                    {
                        "type": "text",
                        "object_relation": "business",
                        "value": "Pharmaceutical"
                    },
                    {
                        "type": "phone-number",
                        "object_relation": "phone-number",
                        "value": "1234567890"
                    },
                    {
                        "type": "link",
                        "object_relation": "website",
                        "value": "https://umbrella.org"
                    },
                    {
                        "type": "text",
                        "object_relation": "registration-number",
                        "value": "11223344556677889900"
                    },
                    {
                        "type": "attachment",
                        "object_relation": "logo",
                        "value": "umbrella_logo",
                        "data": b64encode(f.read()).decode()
                    }
                ]
            }
        ]
    return event


def get_event_with_lnk_object():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
        event['Event']['Object'] = [
            {
                "name": "lnk",
                "descrption": "LNK object describing a Windows LNK binary file (aka Windows shortcut)",
                "meta-category": "file",
                "uuid": "153ef8d5-9182-45ec-bf1c-5819932b9ab7",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "filename",
                        "object_relation": "filename",
                        "value": "oui"
                    },
                    {
                        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                        "type": "text",
                        "object_relation": "fullpath",
                        "value": "/var/www/MISP/app/files/scripts/tmp"
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
                        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                        "type": "malware-sample",
                        "object_relation": "malware-sample",
                        "value": "oui|8764605c6f388c89096b534d33565802",
                        "data": b64encode(f.read()).decode()
                    },
                    {
                        "type": "size-in-bytes",
                        "object_relation": "size-in-bytes",
                        "value": "35"
                    },
                    {
                        "type": "datetime",
                        "object_relation": "lnk-creation-time",
                        "value": "2017-10-01T08:00:00Z"
                    },
                    {
                        "type": "datetime",
                        "object_relation": "lnk-modification-time",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "type": "datetime",
                        "object_relation": "lnk-access-time",
                        "value": "2021-01-01T00:00:00Z"
                    }
                ]
            }
        ]
    return event


def get_event_with_mutex_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_MUTEX_OBJECT)
    ]
    return event


def get_event_with_netflow_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_NETFLOW_OBJECT)
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


def get_event_with_news_agency_object():
    event = deepcopy(_BASE_EVENT)
    with open(_TESTFILES_PATH / 'AFP_logo.png', 'rb') as f:
        event['Event']['Object'] = [
            {
                "name": "news-agency",
                "description": "News agencies compile news and disseminate news in bulk.",
                "meta-category": "misc",
                "uuid": "d17e31ce-5a7a-4713-bdff-49d89548c259",
                "timestamp": "1603642920",
                "Attribute": [
                    {
                        "type": "text",
                        "object_relation": "name",
                        "value": "Agence France-Presse"
                    },
                    {
                        "type": "text",
                        "object_relation": "address",
                        "value": "13 place de la Bourse, 75002 Paris"
                    },
                    {
                        "type": "email-src",
                        "object_relation": "e-mail",
                        "value": "contact@afp.fr"
                    },
                    {
                        "type": "phone-number",
                        "object_relation": "phone-number",
                        "value": "(33)0140414646"
                    },
                    {
                        "type": "text",
                        "object_relation": "address",
                        "value": "Southern Railway Building, 1500 K Street, NW, Suite 600"
                    },
                    {
                        "type": "email-src",
                        "object_relation": "e-mail",
                        "value": "contact@afp.us"
                    },
                    {
                        "type": "phone-number",
                        "object_relation": "phone-number",
                        "value": "(1)2024140600"
                    },
                    {
                        "type": "link",
                        "object_relation": "link",
                        "value": "https://www.afp.com/"
                    },
                    {
                        "type": "attachment",
                        "object_relation": "attachment",
                        "value": "AFP_logo.png",
                        "data": b64encode(f.read()).decode()
                    }
                ]
            }
        ]
    return event


def get_event_with_object_references():
    ap_object = deepcopy(_TEST_ATTACK_PATTERN_OBJECT)
    as_object = deepcopy(_TEST_ASN_OBJECT)
    btc_object = deepcopy(_TEST_BTC_WALLET_OBJECT)
    coa_object = deepcopy(_TEST_COURSE_OF_ACTION_OBJECT)
    ip_object = deepcopy(_TEST_IP_PORT_OBJECT)
    person_object = deepcopy(_TEST_PERSON_OBJECT)
    vuln_object = {
        "name": "vulnerability",
        "meta-category": "vulnerability",
        "description": "Vulnerability object describing a common vulnerability",
        "uuid": "651a981f-6f59-4609-b735-e57efb9d44df",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "vulnerability",
                "object_relation": "id",
                "value": "CVE-2021-29921"
            },
            {
                "type": "text",
                "object_relation": "summary",
                "value": "In Python before 3.9.5, the ipaddress library mishandles leading zero characters in the octets of an IP address string."
            }
        ],
        "ObjectReference": [
            {
                "referenced_uuid": ip_object['uuid'],
                "relationship_type": "affects"
            }
        ]
    }
    ap_object['ObjectReference'] = [
        {
            "referenced_uuid": ip_object['uuid'],
            "relationship_type": "threatens"
        }
    ]
    as_object['ObjectReference'] = [
        {
            "referenced_uuid": ip_object['uuid'],
            "relationship_type": "includes"
        }
    ]
    btc_object['ObjectReference'] = [
        {
            "referenced_uuid": ip_object['uuid'],
            "relationship_type": "connected-to"
        }
    ]
    coa_object['ObjectReference'] = [
        {
            "referenced_uuid": vuln_object['uuid'],
            "relationship_type": "protects-against"
        }
    ]
    person_object['ObjectReference'] = [
        {
            "referenced_uuid": ip_object['uuid'],
            "relationship_type": "owns"
        }
    ]
    ip_object['Attribute'][0]['to_ids'] = True
    ip_object['ObjectReference'] = [
        {
            "referenced_uuid": coa_object['uuid'],
            "relationship_type": "protected-with"
        }
    ]
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        ap_object,
        as_object,
        btc_object,
        coa_object,
        ip_object,
        person_object,
        vuln_object
    ]
    return event


def get_event_with_organization_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "organization",
            "description": "An object which describes an organization.",
            "meta-category": "misc",
            "uuid": "fe85995c-189d-4c20-9d0e-dfc03e72000b",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name",
                    "value": "Computer Incident Response Center of Luxembourg"
                },
                {
                    "type": "text",
                    "object_relation": "description",
                    "value": "The Computer Incident Response Center Luxembourg (CIRCL) is a government-driven initiative designed to gather, review, report and respond to computer security threats and incidents."
                },
                {
                    "type": "text",
                    "object_relation": "address",
                    "value": "16, bd d'Avranches, L-1160 Luxembourg"
                },
                {
                    "type": "email-src",
                    "object_relation": "e-mail",
                    "value": "info@circl.lu"
                },
                {
                    "type": "phone-number",
                    "object_relation": "phone-number",
                    "value": "(+352) 247 88444"
                },
                {
                    "type": "text",
                    "object_relation": "role",
                    "value": "national CERT"
                },
                {
                    "type": "text",
                    "object_relation": "alias",
                    "value": "CIRCL"
                }
            ]
        }
    ]
    return event


def get_event_with_patterning_language_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "uuid": "c8c418e3-b61c-4d40-a1fc-b10cec6585d7",
            "meta-category": "misc",
            "description": "An object describing a Sigma rule (or a Sigma rule name).",
            "name": "sigma",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "sigma",
                    "object_relation": "sigma",
                    "value": "title: Ps.exe Renamed SysInternals Tool description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A report reference: https://www.us-cert.gov/ncas/alerts/TA17-293A author: Florian Roth date: 2017/10/22 logsource: product: windows service: sysmon detection: selection: EventID: 1 CommandLine: 'ps.exe -accepteula' condition: selection falsepositives: - Renamed SysInternals tool level: high"
                },
                {
                    "type": "text",
                    "object_relation": "context",
                    "value": "disk"
                },
                {
                    "type": "link",
                    "object_relation": "reference",
                    "value": "https://www.us-cert.gov/ncas/alerts/TA17-293A"
                },
                {
                    "type": "text",
                    "object_relation": "sigma-rule-name",
                    "value": "Ps.exe"
                },
                {
                    "type": "comment",
                    "object_relation": "comment",
                    "value": "Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A"
                }
            ]
        },
        {
            "uuid": "efc15547-4fe9-4188-aa71-b688e1bfa59c",
            "meta-category": "network",
            "description": "An object describing a suricata rule",
            "name": "suricata",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "snort",
                    "object_relation": "suricata",
                    "value": "alert http any 443 -> 8.8.8.8 any"
                },
                {
                    "type": "text",
                    "object_relation": "version",
                    "value": "3.1.6"
                },
                {
                    "type": "comment",
                    "object_relation": "comment",
                    "value": "To rule them all"
                },
                {
                    "type": "link",
                    "object_relation": "ref",
                    "value": "https://suricata.readthedocs.io/en/suricata-6.0.4/index.html"
                }
            ]
        },
        {
            "uuid": "cafdd27e-c3e2-4f7a-88b4-4c1c98f18be7",
            "meta-category": "misc",
            "description": "An object describing a YARA rule (or a YARA rule name) along with its version.",
            "name": "yara",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "yara",
                    "object_relation": "yara",
                    "value": 'rule torcryptomining { meta: description = "Tor miner - broken UPX magic string" strings: $upx_erase = {(00 FF 99 41|DF DD 30 33)} condition: $upx_erase at 236 }'
                },
                {
                    "type": "text",
                    "object_relation": "version",
                    "value": "4.1.0"
                },
                {
                    "type": "comment",
                    "object_relation": "comment",
                    "value": "To rule them all"
                },
                {
                    "type": "text",
                    "object_relation": "yara-rule-name",
                    "value": "Ultimate rule"
                }
            ]
        }
    ]
    return event


def get_event_with_pe_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_PE_OBJECT),
        deepcopy(_TEST_PE_SECTION_OBJECT)
    ]
    return event


def get_event_with_person_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_PERSON_OBJECT)
    ]
    return event


def get_event_with_process_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_PROCESS_OBJECT)
    ]
    return event


def get_event_with_process_object_v2():
    event = deepcopy(_BASE_EVENT)
    process_object = deepcopy(_TEST_PROCESS_OBJECT)
    process_object['Attribute'].extend(
        [
            {
                "uuid": "d85eeb1a-f4a2-4b9f-a367-d84f9a7e6303",
                "type": "text",
                "object_relation": "parent-command-line",
                "value": "grep -nrG iglocska /home/viktor/friends.txt"
            },
            {
                "uuid": "0251692e-6bb8-4de5-9e94-4dfa2834b032",
                "type": "text",
                "object_relation": "parent-process-name",
                "value": "Friends_From_H"
            }
        ]
    )
    event['Event']['Object'] = [
        process_object
    ]
    return event


def get_event_with_registry_key_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_REGISTRY_KEY_OBJECT)
    ]
    return event


def get_event_with_script_objects():
    event = deepcopy(_BASE_EVENT)
    script_to_malware_object = deepcopy(_TEST_SCRIPT_OBJECT)
    script_to_malware_object['uuid'] = 'ce12c406-cf09-457b-875a-41ab75d6dc4d'
    script_to_malware_object['Attribute'].extend(
        [
            {
                "type": "text",
                "object_relation": "comment",
                "value": "A script that infects command line shells"
            },
            {
                "type": "filename",
                "object_relation": "filename",
                "value": "infected.py"
            },
            {
                "type": "text",
                "object_relation": "script",
                "value": "print('You are infected')"
            },
            {
                "type": "attachment",
                "object_relation": "script-as-attachment",
                "value": "infected.py",
                "data": "cHJpbnQoJ1lvdSBhcmUgaW5mZWN0ZWQnKQo="
            },
            {
                "type": "text",
                "object_relation": "state",
                "value": "Malicious"
            }
        ]
    )
    script_to_tool_object = deepcopy(_TEST_SCRIPT_OBJECT)
    script_to_tool_object['uuid'] = '9d14bdd1-5d32-4b4d-bd50-fd3a9d1c1c04'
    script_to_tool_object['Attribute'].extend(
        [
            {
                "type": "text",
                "object_relation": "comment",
                "value": "A peaceful script"
            },
            {
                "type": "filename",
                "object_relation": "filename",
                "value": "hello.py"
            },
            {
                "type": "text",
                "object_relation": "script",
                "value": "print('Hello World')"
            },
            {
                "type": "attachment",
                "object_relation": "script-as-attachment",
                "value": "hello.py",
                "data": "cHJpbnQoJ0hlbGxvIFdvcmxkJykK"
            },
            {
                "type": "text",
                "object_relation": "state",
                "value": "Harmless"
            }
        ]
    )
    event['Event']['Object'] = [
        script_to_malware_object,
        script_to_tool_object
    ]
    return event


def get_event_with_url_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_URL_OBJECT)
    ]
    return event


def get_event_with_user_account_object():
    event = deepcopy(_BASE_EVENT)
    user_account = deepcopy(_TEST_USER_ACCOUNT_OBJECT)
    with open(_TESTFILES_PATH / 'octocat.png', 'rb') as f:
        user_account['Attribute'][-1]['data'] = b64encode(f.read()).decode()
    user_account['Attribute'].extend(
        [
            {
                "type": "text",
                "object_relation": "account-type",
                "value": "unix"
            },
            {
                "type": "datetime",
                "object_relation": "password_last_changed",
                "value": "2020-10-25T16:22:00Z"
            }
        ]
    )
    event['Event']['Object'] = [user_account]
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


def _get_hash_attributes(to_ids):
    for attribute_type, attribute in get_hash_attributes().items():
        misp_attribute = {
            'type': attribute_type,
            'category': 'Payload delivery',
            'timestamp': "1603642920",
            'comment': f'{attribute_type.upper()} test attribute',
            'to_ids': to_ids
        }
        misp_attribute.update(attribute)
        yield misp_attribute


def _get_hash_composite_attributes(to_ids):
    hash_attributes = get_hash_attributes()
    index = 1
    for attribute_type, attribute in hash_attributes.items():
        misp_attribute = {
            'uuid': attribute['uuid'],
            'type': f'filename|{attribute_type}',
            'category': 'Payload delivery',
            'value': f"filename{index}|{attribute['value']}",
            'timestamp': "1603642920",
            'comment': f'Filename|{attribute_type} test attribute',
            'to_ids': to_ids
        }
        index += 1
        yield misp_attribute


def get_hash_attributes():
    return {
        'md5': {
            'value': 'b2a5abfeef9e36964281a31e17b57c97',
            'uuid': '34cb1a7c-55ec-412a-8684-ba4a88d83a45'
        },
        'sha1': {
            'value': '2920d5e6c579fce772e5506caf03af65579088bd',
            'uuid': 'f2259650-bc33-4b64-a3a8-a324aa7ea6bb'
        },
        'sha224': {
            'value': '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9',
            'uuid': '90bd7dae-b78c-4025-9073-568950c780fb'
        },
        'sha256': {
            'value': '7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4',
            'uuid': '2007ec09-8137-4a71-a3ce-6ef967bebacf'
        },
        'sha384': {
            'value': 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce',
            'uuid': 'c8760340-85a9-4e40-bfde-522d66ef1e9f'
        },
        'sha512': {
            'value': '28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe',
            'uuid': '55ffda25-c3fe-48b5-a6eb-59c986cb593e'
        },
        'ssdeep': {
            'value': '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi',
            'uuid': '9060e814-a36f-45ab-84e5-66fc82dc7cff'
        },
        'authentihash': {
            'value': 'b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc',
            'uuid': '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f'
        },
        'imphash': {
            'value': '68f013d7437aa653a8a98a05807afeb1',
            'uuid': '518b4bcb-a86b-4783-9457-391d548b605b'
        },
        'pehash': {
            'value': 'ffb7a38174aab4744cc4a509e34800aee9be8e57',
            'uuid': '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
        },
        'sha512/256': {
            'value': '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
            'uuid': '2d35a390-ccdd-4d6b-a36d-513b05e3682a'
        },
        'tlsh': {
            'value': 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297',
            'uuid': '7467406e-88d3-4856-afc9-412459bc3c8b'
        },
        'vhash': {
            'value': '115056655d15151138z66hz1021z55z66z3',
            'uuid': 'cea8c6f6-696c-41cc-b7c7-2566ca0b0975'
        },
        'sha3-256': {
            'value': '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4',
            'uuid': 'e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6'
        }
    }

################################################################################
#                              FEED TEST SAMPLES.                              #
################################################################################

def get_attributes_feed():
    return [
        {
            "Attribute": {
                "category": "Network activity",
                "type": "ip-src",
                "to_ids": True,
                "uuid": "7a8932ed-aef2-4e49-84aa-a5499df161ad",
                "timestamp": "1657805146",
                "value": "1.1.1.1"
            },
            "Event": {
                "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c","info": "MISP-STIX-Converter test event",
                "date": "2020-10-25",
                "timestamp": "1603642920",
                "Orgc": {
                    "name": "MISP-Project",
                    "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
                }
            },
        },
        {
            "Attribute": {
                "category": "Network activity",
                "type": "ip-src",
                "to_ids": True,
                "uuid": "ed07dc1a-6a47-4eb5-910a-9a18407c4217",
                "timestamp": "1657805146",
                "value": "8.8.8.8"
            },
            "Event": {
                "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "info": "MISP-STIX-Converter test event",
                "date": "2020-10-25",
                "timestamp": "1603642920",
                "Orgc": {
                    "name": "MISP-Project",
                    "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
                }
            },
        },
        {
            "Attribute": {
                "category": "Network activity",
                "type": "ip-src",
                "to_ids": True,
                "uuid": "14c5e9f3-e959-4359-925c-013bbb04d2b3",
                "timestamp": "1657805146",
                "value": "1.2.3.4"
            },
            "Event": {
                "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "info": "MISP-STIX-Converter test event",
                "date": "2020-10-25",
                "timestamp": "1603642920",
                "Orgc": {
                    "name": "MISP-Project",
                    "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
                }
            },
        },
        {
            "Attribute": {
                "category": "Network activity",
                "type": "ip-src",
                "to_ids": True,
                "uuid": "23a320d1-3cfd-46e6-8cdb-0f71088560f5",
                "timestamp": "1657805146",
                "value": "5.6.7.8"
            },
            "Event": {
                "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "info": "MISP-STIX-Converter test event",
                "date": "2020-10-25",
                "timestamp": "1603642920",
                "Orgc": {
                    "name": "MISP-Project",
                    "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
                }
            }
        }
    ]
