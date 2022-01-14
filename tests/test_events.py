#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy

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
                "data": "'UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA=='",
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
            "value": "google_screenshot.png",
            "data": "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"
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
    "name": "Attack Pattern",
    "type": "mitre-attack-pattern",
    "description": "ATT&CK Tactic",
    "GalaxyCluster": [
        {
            "uuid": "dcaa092b-7de9-4a21-977f-7fcb77e89c48",
            "type": "mitre-attack-pattern",
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
            "type": "mitre-course-of-action",
            "value": "Automated Exfiltration Mitigation - T1020",
            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
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
                "synonyms": [
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
    "timestamp": "1603642920",
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
    "timestamp": "1603642920",
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
            "uuid": "3b940996-f99b-4bda-b065-69b8957f688c",
            "type": "email-dst",
            "object_relation": "to",
            "value": "jfk@gov.us"
        },
        {
            "uuid": "b824e555-8609-4389-9790-71e7f2785e1b",
            "type": "email-dst-display-name",
            "object_relation": "to-display-name",
            "value": "John Fitzgerald Kennedy"
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
            "object_relation": "bcc",
            "value": "marie.curie@nobel.fr"
        },
        {
            "uuid": "bf64f806-1660-4790-8f07-b116eb41b9bc",
            "type": "email-dst-display-name",
            "object_relation": "bcc-display-name",
            "value": "Marie Curie"
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
            "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
            "object_relation": "altitude",
            "value": "55"
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
            "value": "2020-10-25T16:22:00"
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
            "type": "text",
            "object_relation": "summary",
            "value": "It is compromised"
        },
        {
            "type": "text",
            "object_relation": "type",
            "value": "Report"
        },
        {
            "type": "attachment",
            "object_relation": "report-file(s)",
            "value": "report.md",
            "data": "VGhyZWF0IFJlcG9ydAoKSXQgaXMgY29tcHJvbWlzZWQK"
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
                "date_sighting": "1603642925",
                "type": "0",
                "Organisation": {
                    "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f",
                    "name": "CIRCL"
                }
            },
            {
                "date_sighting": "1603642950",
                "type": "0",
                "Organisation": {
                    "uuid": "7b9774b7-528b-4b03-bbb8-a0dd9e546183",
                    "name": "E-Corp"
                }
            },
            {
                "date_sighting": "1603642930",
                "type": "1",
                "Organisation": {
                    "uuid": "93d5d857-822c-4c53-ae81-a05ffcbd2a90",
                    "name": "Oscorp Industries"
                }
            },
            {
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
                "date_sighting": "1603642925",
                "type": "0",
                "Organisation": {
                    "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f",
                    "name": "CIRCL"
                }
            },
            {
                "date_sighting": "1603642950",
                "type": "1",
                "Organisation": {
                    "uuid": "7b9774b7-528b-4b03-bbb8-a0dd9e546183",
                    "name": "E-Corp"
                }
            },
            {
                "date_sighting": "1603642940",
                "type": "0",
                "Organisation": {
                    "uuid": "93d5d857-822c-4c53-ae81-a05ffcbd2a90",
                    "name": "Oscorp Industries"
                }
            },
            {
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
    base_event['Event']['date'] = '2020-10-25'
    base_event['Event']['timestamp'] = '1603642920'
    base_event['Event']['published'] = True
    base_event['Event']['publish_timestamp'] = "1603642920"
    return base_event


def get_event_with_escaped_values_v20():
    return deepcopy(_EVENT_FOR_ESCAPING_TESTS)


def get_event_with_escaped_values_v21():
    event = deepcopy(_EVENT_FOR_ESCAPING_TESTS)
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


def get_event_with_intrusion_set_galaxy():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Galaxy'] = [
        deepcopy(_TEST_INTRUSION_SET)
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
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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

_PORT_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "port",
    "category": "Network activity",
    "value": "8443",
    "timestamp": "1603642920",
    "to_ids": False
}

_SIZE_IN_BYTES_ATTRIBUTE = {
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "size-in-bytes",
    "value": "1234",
    "category": "Other",
    "timestamp": "1603642920",
    "to_ids": False
}

_USER_AGENT_ATTRIBUTE = {
    "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
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
            "data": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK",
            "timestamp": "1603642920"
        }
    ]
    return event


def get_event_with_campaign_name_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "campaign-name",
            "category": "Attribution",
            "value": "MartyMcFly",
            "timestamp": "1603642920",
            "to_ids": False
        }
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
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "malware-sample",
            "category": "Payload delivery",
            "value": "oui|8764605c6f388c89096b534d33565802",
            "data": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
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
            "category": "Artifact dropped",
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


def get_event_with_url_attribute():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Attribute'] = [
        {
            "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "type": "url",
            "category": "Network activity",
            "value": "https://misp-project.org/download/",
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
    event['Event']['Object'] = [
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
                    "value": "marcopolo"
                },
                {
                    "type": "link",
                    "object_relation": "link",
                    "value": "https://facebook.com/marcopolo"
                }
            ]
        },
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
                    "value": "johndoe"
                },
                {
                    "type": "text",
                    "object_relation": "displayed-name",
                    "value": "John Doe"
                },
                {
                    "type": "text",
                    "object_relation": "followers",
                    "value": "666"
                }
            ]
        }
    ]
    return event


def get_event_with_account_objects_with_attachment():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
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
                    "value": "octocat.png",
                    "data": "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAAAAXNSR0IB2cksfwAAAAlwSFlzAAALEwAACxMBAJqcGAAAL+RJREFUeNrtXYlbTdv7P\/\/E19ScSqRJAypTg7poNGYKESEN5gwZCokylWQqKhq4EjLl3gplKFSoRDSnNGpU\/N7r+HW7qbX3OWefdfY+rfd5n\/vcJ\/ucs\/be72e9w3oH3uD\/\/Y8w4QHLPPIICBMAECZMAECYIR5naDjTwcF52TJPDw+fnTsDDh4MO3Xq8qVLN27cSE1Nffnixfv376urq3\/8PzU2NlZVVRUVFb158yYzM\/NhWtq9u3evJyTEXL58\/vz54ODgg\/7+q11dzc3M5GVlyeMlAGARg0SaTp680sXlUEBAwrVrIMHt7e0\/xEZdXV0fP34EeAAq3Netm2ZlpaKsTN4CAQA+\/sPScr2X18mQkOT794uLi3+wgCorK9NSU0+Hha1xddXR1ibviACASR4yaBDs8Tt37Lh75w7YKj9YT6AioqOi1q5ePUZXl7w+AgAhefzYsRs3bACrpqam5gdn6dOnT5eio93WrCFgIACgZm1NTdg4wfUsKy39IXUEBhs44m5r1+oRMBAA9GRlRUVPD4+nT5\/+GDCUm5u7zdt7hJoaefsDGgA21tawKTY3N\/8YkNTR3p6YmLhg\/vxhQ4YQAAwg1tTQ8N279\/379z8I\/aSqqqoTx48bjR9PACDlvGTx4uT794nE90eZmZlenp4KcnIEAFLFWqNHBwcH19bW4gy\/pKWm3rhxIyoyMiQ4+MD+\/Vu3bFnj6rpwwQLr6dMnmpjoaGkpKSjwlwe2uK6OjrGRkYW5ua2NjeO8ec7LloG3unnTpt27dh0KCLgSH5+Vmdna2opn8fV1dQf9\/dVUVQkAOM862trnz58X6+ks4AocaPAlwKxa6uQEwi07bJj4kOxgb79pw4ZToaHJyckAs66uLjHdV1NTU\/CJE6NHjSIA4CSP0dW9eOGCmEIoIT8zEWAvVx0+XOJ3am5q6uHuHhcXV15eLo77jQgPl+JjBCkEgIGe3qXo6G\/fvjEoBEVFRSAHy52dWR46HGtgAEY8mEyVlZUM3n5nZycAbIKJCQEA29MwY2Nj4W0xFRsBSYLNlaMJNkbjx2\/6eZjdM\/NUFPr+\/XtSUtJUCwsCADa+7KtXrjBiEDc2NkZHRYEzKk3pTDYzZoAGq2MoDJB4\/bq2piYBAFvOcc+eOSO66MM3\/PXXX6tdXaU45x68c6dFi64nJLS1tYn4uJqbm\/fs3i0zdCgBgCR5xfLlFRUVIr7Lgvz8vXv2aGpoDJzg93AlJXDiU1NTRdw4Ct+947qq5CoAdHV00lJTRQxfnjt71nLq1IGcDAKw3+Xjk5OTI8qTvPbnn9y1iDgJAD9fX1Fe2P1795Y6OZE8sJ4MG8HdO3eEfqStra27d+0iABA7W1lagtoV2sqHvWpgZrzQ5AkmJvFxcUKH0bhoEXEGAGoqKlGRkd+\/fxcujA3vdZyhIRFxmmeI4eHhQh+fnzl9Wnxn4QMUADOmTauqqhLiZXz79i3m8mUDPT0i1oLy6FGjgoODv379Ktxh+VgDAwIAZmLY+\/z8hFDKHR0dkRcvklJA0RXvQX9\/IfIIW1paVixfTgAgEo9QU0tJSRH00YPuBg1O+iMwyCrKyqfDwoTYhmJiYhTl5QkAhDR7hMjuSn\/8WH\/MGCKy4uApkyZlZWYKkUZlOnkyAYBgvGf3bkGz2Wpqata4uhIxFbdF6uHu\/uXLF0F1svfWrQQAdM0eQYu2vn\/\/Hh0VBdYqEVBsjkFEeLigp8j37t5lYZENuwBgZWkpqNkDGhaMJSKUEqhDMDPLfvVK0CZ206ysCAD6Zp+dOzs6OgRSrAEHD8rKyBBZlKBFtHnjxvr6eoEC06vZZKnyWPIcwYYRaC95+vQpVyLNUs86WloCdVUCkxVgQwDwi2WGDr2ekCDQFsLRtBMp5mFDhhw\/dkygc\/oD+\/cTAPxPTkZGIJe3pqaGWPysZcd58wSquTkVGgrKf+ACQElBIT09XSCzZ0Bl7XPUHBLorCA+Lm7o4MEDEQBqKiqvXr6k\/6SCg4MHcgc\/DjHYtPCy6JtDSUlJcpKLZEgGAOpqavl5efQb1CxetIgIFufMoYaGBrrn9+np3W3CpB8A2pqa9PtyFuTnk1xO7qZV0zeHwBxQl0TLGdwAGGdoSL\/7fkxMzIDqUymVnHj9Os3XDUYBfgzwMEs\/\/YErLAmTERadIy9epPnSX2RlYbaFeDjt\/tKSEpq1i6tJWpt08ZGgIJoYSEtNxdltBRMAANbZ2dk0ExzAfyISI328dcsWmqGh6wkJ2M4HcABg2JAhNFuYNDU1Tf\/jDyIr0sorXVxo5pCeO3tWegAQFxdH85R3ojS2XyXckxcuWECz3B6PEyh2AAQFBtK525KSEjK9cICw9fTpoOrpSIWnhwe3AbDey4tmEwGNkSOJZAyoWgKa\/SbE3cJMjABYtHAhTelXUVYmMjHQ2M7WlmZcyN7OjnsAsLK0pNOCuKKiQuqH8BDujxcvWkTHJ66vrxdfowOxAGCsgQGdKiG4hjQqHOAMVj5NM0FM3eaYB4CivDydVJ+O9nbQEkQCCB\/096fZcZEbAKBT3AiKjyR4Eu7mqMhIOhhwEoPMMAwA8NlZEt4izCEeOngwnbLYpqYmxp0BJgGgo61NJ7579MgR8so5zUMGDZKXlVUdPlxj1ChtLa0xOjrAWpqaqiK0ZpIZOpROugDjzgCPQRDTSf4GoDPyc8OVlEKCg\/Py8srKyiorKoo\/fXr58uXtpCSwFLds3jzTwUGd3fNMOccg8aPU1adaWLivWwcP+f69e69evSotKamrrW1uboaN7\/Pnz\/BHUcbI0kwYiwgPZyMA6Jz4MpXoBzuQ2ZQpJSUl3\/9L4Fp0dnbCy\/j48eOjhw9DT55c5eIyZfJkBTk5iRdfc3Snh0enNXr0nFmzfPfuTbh2DXYcEPT+2jc11Nf\/YWUlSo2vpoYGnb6LDPadZgYANjNmUCb6lZeVwbbNyM\/BWwEvgvIXAQ8tLS0F+fmHAgLs7eyUFRWJTNMXfTkZGaNx4zzWrYuNiQEFS7M19DZvbxGf8ywHB8o3C6+VqXEnDABATUWFcnoFyCKDQU89Xd2kW7cE6sQEmxaohe3bto01MODQ\/BKJ+KNgPTrY2x8JCoLNWNCRPMnJyePGjhVxDceOHqVTPsbIQFsGAACWH+Vy9+\/bx+BLmjVzZkFBgXADYwoLCyMiIvT19IhR9Puur6KsDBtwUlJSRUWFcJPCioqKFjg64vEnwQmUPAC2btlCudCMjAwGpQ2ezu5du1pbWoQeaQi7Wn19\/bVr18BXJnYR\/5GCg+u2di3oVfBoRZnA2d7e7n\/ggOg6VkdbmzKZACAqeiaBSAAA94gytxtug9luVlqamlevXPnBBIFCAF8Z1L0UT4enrFXSGDlynZvb0ydPhBtA+DvdvHlTj4lo\/XxHRzq90iQJADqHF\/NFVoi\/Z9K+ePHiB0P0jzaoq4uOijIzNR1o0q8oL79w\/nzY9YWbhNcfvX79ehpDZX1g5FD+nIe7u2QAYD19OuXizp45w\/hrW7VyJVioP5gmcPjiYmMN9PQY79QHXwgbrczQoXIyMqBqFOTkQPKUFBSUFBWVlZRUVVTA\/Bihqgr293BgJSVg+Ce4AC6D68GcgI8z67HAl1tZWsbHxdHvXUWfPn\/+7OXpycg64aFROgNgYogyG4UntOp8R+WG5uXliaN5f1BQUGNj4w8x0D8W0aNHG7y8dLS0hPAg+YIOUqs5evT4sWMtzM3tbW2dFi\/2WLdu5\/bthwICYDsAVfPn1at37txJSUl5\/OjRs6dPnz9\/npWVlfn8+bNnz9LT09PS0pKTkxMSEmIuX44IDz9+7Jjvnj2bNm50WbECdKn1jBmTJ04EDx5gA0ASAhtw\/UQTk7179rzIyhJoGgN9An1yKjSUwfQCSmcgKjISNwC8t25Fr6mtrW28yOGwPjkpKUnoUeZ0CFb+6tWr2bNmUZ7ZgeSBPMG+DoCZPXPmnt27L1+6BFZpfn5+SUlJbW1ta2srU4Y1378EUSgvK3v\/\/j0YgWBqBx4+vMLZ2XTyZHDGVIcPp3Q9Qck4zp2b9\/at0EOwaXa1efDgAYOK1H3dOsofnWphgQ8AoHEoc35gjxGH9IN58JI5BwB91HL27NleRfp8iVdXU7O1tt7m7X3+3Dl408XFxd\/Es5XSV1zVnz+DJgGTBvTMEicnEyMjsKnAfOpWDoANG2vrmJgYgaa5iOIGaGlqMvjeQV+hf\/HNmzfC9U4WBgAXIiLQq\/n48aOYDpt0tbU\/fPiAR7AAA2CiOC9bpjFypP6YMWDPgClyKToaDBW4webmZgZ3d6Yc+taWlrKystzc3BuJifv37YPFm02ZMn7cOE8Pj1cvX4JGwrMSUIDMBhWmTJpEqfZ9du7EAQBYCuWLn+XgIKbABext4GPhlCpwjsEiT01Nhb2TbRJPxxwHJzLl77+FGPUuCsHPzZk1i9lXH3bqFPpHAd5CBNx5jCujO7dviy9yZ2lhgW0bIySKu+K6ahXj1i9lnlxiYqJ4AbDa1ZXyznV1dMR3YEknU4oQG8h7yxbGA8oAKsa9YZ5AQdkSqu62QYGB4tv+YQGLFy0issUJ8vP1FYcf+OTJE\/Tv3r1zR1wAcFuzBv3blZWVivLyYq3JWLN6NZEtTtCxo0fFMdvB2MiI8vhi0oQJzANgyKBBlL0eGCxT6LcMwN2dyBYnKCQ4WFE8nf5PHD9O4Qlcv848AJyXLkX\/KugmceeuEABwiE6GhIhp1AVYGWBroMPBRuPGMQyAPORMu87OTtBNGADgQeNQkBAbKPjECfHZw16enuhfj42NZRIAjnPnon8vJiYGT132ahpxAEJsoKDAQPElmcvKyKATIru6umg2UKEFAPQ4a4E0DokCDRDau2ePWCcd+ezciV7AhYgIZgAwY9o0ZgNPotTs2dnaknMA9hNswJs2bhRr0SnYw\/V1dYg1dLS3a9PIR6IGQHJyMvpubWbMwFbDMdXcnE7TaUKSpdbW1lUrV4pbGAIOHkQvI+zUKVEBMNHEBP0bL1+8wFnEBLYW5lwgQkJQdXX1THt7cQuDmqoqOi8G\/nWUurpIAEhMTETfKuYet5oaGgX5+UTCWE4f3r8XUzVILz4ZEoJeif+BA8IDwEBPD\/3tIIuYy1jB8svIyCASxmYCJy0rKwtPuw2w8tGLKSoqEh4AlI3b17m54S\/lvnzpklgLmgiJSOCkxcfHY5MHyjH06MG7KAB8\/PgR8b0VFRU4J3p38y4fH8zZ7YQEorq6Ot+9e7HJg\/6YMeg5S+HIZrr9AmCqhQX6PoUrwBGd7Wxs3r17R+SMtVRYWMh4NYwovQnr6+oQean9AuBUaCj6PiU12hE8kzu3bxM5Yy3dvXNnrIEBTpFY7uyMXpLz0qWCAWDYkCHV1dWIbxQo4Y7hY\/Bhw\/x8fb99+0ZEjZ0nAP4HDghXny5Kjgy6txeiSrFvAIAKQ9\/nksWLJdjSzM7W9u3bt0TaWEjFxcUSmf528cIFxKo6OzvVVFUFAEDM5ctCG1UYIqHrvbzQCbGEJEVNTU0hISFCdBYTfUIFemHbt22jCwBKhQJok+D27zh37qtXr4iosZbKy8t99+6VE0NTQDSjg5bZr17RBcCK5cvRdwgWiKQa2I\/R0cnLyyP5cCyn2i9fXFeuxIwBytSgCf9tc9YvAG4nJaHwXVYmqdES4wwNoyIjifRzggoKCpY4OeH0hg319dFLOnH8ODUAwFdAFx0fP3ZMItKvpKAAilVMbXEJMU5dXV2PHj400NPDKSToNJn3799TA2Djhg3oG5s8caJEAOC6ahVlUxZCrCLQ1WGhoTjjJeu9vNBL+r11XG8A3L1zB\/H5\/Lw8iUi\/rrb28+fP0SfehNjpEM+eOZPxDln9sbKiIrpcxG3tWhQAYKHo+I+Yej5T3lVIcDAx\/TlKqSkpYJ1jk5bk+\/cRi\/m9WP4\/ADCdPFkIP1rckR\/HefOKi4uJJHGUGhoa9vn5YTOEdvn4IBZTVVWFAgB67EVdbS3+7X+UuvpfDx6Q7Z\/T9OnTJwszMzzBQ3NTU\/Rieg2W\/A8AEq9fR3xSIvk\/7m5uxPSXAnf47JkzzA4LRXRQrkNmy2\/etKlfAKA\/uWXzZszSP0JV9T7SpCPEFSp8927hggV4xAZdx9urhfq\/AADVgL6HiXgdAIDynFmzxDHGkBB+6ujoOB0WhudsePPGjWhLvmdUikczhorfAVBXU6Mzh5gQV6ggP9\/E2BhH6xCqrdy8x\/imfwEQFxdHX3Fg4IXz55MOKNJEzc3N\/vv34zkTqKqqQqxkt49PHwBAf2brli04pR905elTp7rEOQ6VEHZP+PuTjAzKRj2McExMDGIlycnJvQEwRlcXvXrMGRDjDA0\/FhURoZEyampqcpw7F4MScFu7FrGMr1+\/9gbAGuTwL8wOAGz\/y5ctI7F\/qaSgwEA1FRUMDdTQy+hWRL8AEHryJOLqGzdu4ASAxsiRF6mavRDiKD19+lSgEUZCM3qgka2NzX8AgO6zsM3bGycAplpYZD5\/TmRFKqm8vHy5szMGKboSH49Yxob16\/8DAHTDTZz9n\/nT+BpJ+F9KqaOj4+iRIxgKZdB9DU+Fhv4HAOg59HgOsbsdgOATJ4igSDHdTkoaI7Zh0t3ssmIFYg0PHjz4FwB6yBBQe3s7zu1fRVk56dYtIiVSTDnZ2TOmTRO3IJlNmYJYQ2lJyb8AmOXggLg0NzcXJwC0Ro\/OzckhUiLFVFlRAdszBlMCvQx+XgaPsgwS8xnwtD\/+KCsrI1IixdTY2HgoIACDLJWVliKWYW5m9gsAwcHBiOswV8GvcnGpr68nUiLF1NbWdvXKFQyylJqailjGalfXXwBIQvZB8fL0xNr9fOdO0v5fuqmrq+tJRgaG+pjz584hlhF4+PAvAKCHYNvb2WGT\/mFDhoQg1REh6aCCggIFOTlxi9M2b29K2\/4fAKB3XB1tbZzNf2KRaUyEpIOKP30aPWqUuMVp3pw5iDXwW5zwQL7ZEwNVV1N7QDWVlZAUUFVl5ThDQwzDYxBraGho+AcADvb2iIvy8DYCgl3hyZMnRD6knr7U1GDILx46eDDaFfkHACtdXBAXgX+MuQEWafw\/EAh2XytLSwwShe6TpayoyPNwd0dccSEiAicAxujqopP4CEkHNTU1zZg+HYNEoYsKdbS0eOheQN05Q9gm\/n369InIh9TT169fba2tMUhUYWEhYhkmxsa8vXv2IK44euQIZgAUEwAMAGpubsYzZeJFVhZiGX9YWvIOBQQgrjiwfz9OAOjp6n5CzvkgJDUmkDUWEwh9GDxn1iwe+uAJ8zBgcILJDOCBQI2NjegB7kzxjRs3EMtwXrqUd\/78ecQVmzZswAkAHW3tfOSxNCGpiQL9gSUKdCk6GrEMD3d3HnogpNuaNZhzobPJALwBQPX19Rbm5hgkKuzUKcQydmzfzkM3xHVetgzzQdhTchA2AOjLly94SuPRLu5Bf3\/e\/Xv3EFfMd3TE2g1XTS2ZpEIMAKqqqhprYIBBosCJRSwDHGDeo4cPEVfgTAXl10NeR2okQtJB5eXl2liGaXt5eiKWcfHCBV5WZibiCjzn1d2sKC8fFRlJ5EPqqbi4WE1VFYNErUZ2fIuJieG9efMGcQXmjogyQ4ceO3qUyIfU07t37+BdS3xuZER4OA99VGY5dSrmptC7d+3qJD1xpZq6uroyMzPxiNPOHTsQKwk9eZKHPiqb5eCAGQBgtLW2tBApkWLq6Oi4f+8eHnHav28fYiWBhw\/zbt68ibhiqZMTZgAscXKqq6sjUiLF1NraGh0VhUecjh45gliJn68v1UHYb4OFxc3Tp00rJ21RpJqampoO+vvjEafTYWGIlWzz9uadPXMGcYX31q2YAWCor49OYSXEdaqtrfX08MAjTpHINuOwDN6RoCDEFWBCYQaAmorKs2fPiJRIMRUVFTnOm4dHnK5euYJYyUoXF4p6gBPHj2MGgLKi4k1kBh8hrlNWVtZULIlAwLeRPa8WL1rEQ8+UDA8PxwwAORkZQB2REikm2OA0Ro7EI04pKSnoICcPfVR2JT4eMwCGDBoEmPz27RsRFKkkeLNnTp\/GcwoGjDanp1lZ8RYtXIi44u6dO5gBADzf0ZH0x5VWamhowBlZef36NWIxkydO5NnZ2iKuSH\/8GD8AJk2Y8PjRIyIrUkmlJSWzZ83CJkvorhCG+vo8c1NTxBU5OTn4ATByxIgLERFEVqSS0tPTjcePx+ZPohcDF\/DGGRoirqipqcEPAEV5+c2bNhFZkUo6e+YMbHB4BMl08mTESqqqqv7pDEeJEmVFRcwAGDp4sLmZGUmJk0oPeM3q1Rgm5PHZeelSxGIyMjJ+dYcuKSlBXIenfUVvK0hdnRyHSR+VlZVNNDHBJkXoM66Yy5d\/AeDBgweI67CdWvdk2WHDjgQFkWHx0kRdXV2PHj3CMBagmy9euIBYD7\/nFY+ycj44OBg\/AIAd58378uULkRupoZaWFsxtph6mpSHWs9LFhdaQPIkcBQBra2rmZGcTuZEm+8fc1BSnCKGH5E21sPgFAPRRwIcPHyQCAPDOd\/n4ELmRDgJr9vbt28OVlHCO20IvSUVZ+RcARo8ahbius7MTm9veKyfCdMoUYgVJB339+nWfnx+GwXjdbGJsjFhPXW3tv4OygWF9iKvx9DD6ncFhupGYSKRHCig3J8fyp8mBjdE5Pln\/X5TMo5MzhLk\/3H8qJBcvJrEgrhMYEX6+vpgPlNDl8N1Znjw6PUQxN0nv7Qrn5BAZ4jSVl5eDx4nT\/gGOjY1FLKl7VP0vAOzZvRtx9W28k8J6dQravWsXGZ3NXfr27Rtst\/Kyspglp6qqCrGqtatX\/wcAaIMJPIShgwdLCgN6urpZyOZFhNhMRUVF+LtLoQek9nRrfwFAU0MD\/QELXDVsfSqBFc7OLaRZEAepra0NjA2cp798dlu7lk4I6F8AAL8rKEB8ZrePj6QAwK+UT01J6erqIiLFLcrPyzPQ08MvMNFRUYhV3bp1qw8AoEfFJN+\/L0EAAM+ZPZtMT+Lc9r950yaJSAvYXYiF7di+vQ8ALHd2Zq0bAKykoHAkMJAoAa4QvKmMjIzRo0bhFxVKe75nRgav53AK9MemWVlJVgkY6utfu3aNyBYnqLCw0MbGRiJy4rpqFf2tnNfzk+hW6X6+vpIFAHjDNjNmgAdDxIvl1NjYuMvHR0FeXiJygq6nvXf3bs+LefQbKaakpEgWAPwMp4CAgIaGBiJkrCXYYqOjo\/FHfv6dDo\/0FXfv2tUvAJYsXoz2abC1c0Gw6vDhJ0NCOjo6iKixkDra2+Pj4vR0dSUlHpSWfK+hR7xebQnRXqaNtbXEATBk0KAJJiZX4uNJjhDbCN7Ig+RkMFMlGC\/xcHdHb+K91sbr9Xn0mF5sXa0pq+YnGBvn5uYSDLBK+isqKuxtbWWHDZOgbKB7If7111+9ru8NgJDgYMTnJdImqD+ePHFiTnY2wQBLpD8\/Lw\/\/NIlerDFyJFoe9vn5UQBgwfz56FudgLGqn1IP2NvZgc4lhwOSpc7OzkePHi1xcsKf8daLvbduRS91yqRJFACgdAPAAWWPEhg2ZAjc0rNnzwgGJCj9r16+tLO1lZORkbg8oMtaQEf9\/hHe73\/6+++\/Ed9SXV0tkQpJdM1AXFwcSZnGT62trcn377PEKNDR1kavts+DLJ6gs4WBFi5YwCoADBk0SE1V9XRYGImN4iTYcSIvXgQNjLnSpT\/23bsXvWBACC0AgCWHLhFOvH6dVQDo7iKx3svr\/fv3xC0WN4HBmZeXt83bm99YgSWcm5uLWPPTp0\/7\/BSvz79evnQJddjR0YFnzr0QRfT2traglBvq64mYiolgc4QnPH\/ePJw9TujkiaGXvWXzZgEAYG9nh\/66zRs3shAAv84CVVU9PTzKy8qIKmA81llYWAiWtERyPNF8+NAhtKfe35bN68+qRg\/rzcI16l5or2CsgcHZM2dKS0tJl2lGbB4Q\/bBTpyaamLAtBMLnjx8\/ItaPqGbh9fcPgYcPox+KsZERmzEArD5ixOJFi2JjYr7U1BAYCEdg7lZUVFyJj3davBjbZDtBeaqFBfouVru6CgwASqPq2NGjLAcAXxWAo7Z506aHaWlgvBKjSCD6\/Pnz3bt3vTw9tTQ1WRLq6ZPj4uIQd9HW1oY4oeMhvvf58+eI762pqRE05RUeourw4ROMjW2srefNmbNg\/nz4n8mTJmmNHg2KVayPmO8fJyYmVlZWkmgpmlpaWoo+fIiLjQVXEP94FCFOgdAzRa\/9+Sfi4ygAoEcIA+3csUOgwUe7fHxevXwJKrW1tRXMStiP4VlXVVXl5+dfv34d\/tXWxgYQIj4kKCooWE2dut3bG4zCT58+wd5AjpC7rfyGhoZ3795dvXJlg5eXuampmooK+zU8MHh66FtbtHChkAAAxxn91SDK9PN2pllZgdyj30FlRcXpsDALc3OxZhQCwEapqy9csACeXU5OTlNj40D2EGD7LCsre\/rkCXh9jvPmsTDCg56nCLsY4u5qe3RAERgAwIlUvWk3bdhAEwA2M2ZQ2B7fvwMGQBZhKwL9azx+PIb6GzkZmRnTp4cEB\/\/9998fP34EiIJASLerAHcHt1lXV5eXl3f50qUd27ZNNTeXeB6bOKKfP2gk8FMAwHr6dPQPFBcX0xRTsCb\/+usvxFeVlpb67t27ysUlIyMDYFBYWOjp4YEnuRzwOUJVFSDn4e5+OTr67Zs31dXVICXShATYXOpqawsKCm7fvh0UGLh0yRJDfX0wOCXb7ENEv66+rg5xy\/AGKU9seZQ\/k\/74MfrJ0s8CNxo\/\/uWLF\/1JFcCDH2gDQUxLTeVrZ9ii4I+YQxCgFkyMjZ0WLwYnJzIy8tHDh6UlJaBMv379CkqM\/aiA7aOpqamqsvLDhw+ZmZkJCQmHAgJgZwElPNbAQLIFKwyyz86d6OdwKjSU8kuoATB39mz0z8BWTXMXgcumT5t27969Pm2hysrKgICAiSYm9nZ2Dx8+7I5hXY2Pl1TGFcjKqJEjxxoa\/mFpuXzZMrAWToaExMbE3Lt799mzZ+AyopOmMJvyOdnZSbduRUVGBp84sWvnTteVKx3s7EyMjHS1tWGnZ+cBligtQsAFRT8QbU1NBgAADNs2+umvWL5coKr2o0eO1PbV3QTUNNzV58+fewZn+NVGppMns0RZwzKUFBQ0NTRcV6368P49e06sQk+eBFmXmg0eze7r1qEfCNgOdL6HFgCcFi1C\/9jbt28FLWSxsbb+68EDRPgF\/un5s2eRFy+WlJQABl6\/fj1v7lyWYADU0ZxZs15Q7QuYCfza0NBQCfYjwfn8we5AO\/pG48YxBgD4PRBxUaKtfe6j4ISBlVZeXt6nVQ1u6JzZs8E3ne\/omJubCzoBHAOwoFiSaPT40SO2HajBY6ypqfF0d+doSIc+r3NzQz+KJNoTLXg0r1vp4oL+yXcFBUJYmWBLeG\/dChjo8xzewsyMb+1t+nkkBwKXnJws8R1uuJIS4Ja1rnBBQUGv1jdSxvD8KUcnTqU9j4xHf8NGKx0g4cYgwzebGBvDl\/cSKf5gcf0xY0DiFy1Y0P1H8B9GSK4aAdDo5eGBPnyRuB7IzcnR0dKSVgCAq4N+AumPH9P\/Nh6DbkdTU5PW6NHCYWDZ0qXZr171wgA48g8fPgw7daqnF15WVrZq5UpJOQPGRkYpyJppNlB7e7tAWSocYnj+lMf2jvPmiQUAsPkVFxejf\/vPq1eF3lldV63q0xb6fYd78OCBRMYuAOr8\/PwaGxvZf+yVk52tMny49AHgyZMnzMZjeAJdvXnTJspHbz19upAYGDbMeelSRL4Q+ACgZGADgGvOnT2LXwmMHjXqPWvinpRKYMf27dw95e2TQTwob9zB3l6MAJAdNgxdesP3hoUORcvLygafONGnjmtvazsTFvaHldWFiIj6+vovNTVWU6fiPB0DF3+1qyuHskcfP348Sl1daqRfTkamrLQUfctCjDPlCfqBWQ4OlI++VwdqgRjeWZ8pQxUVFfxR4\/Jycgf27wf3IPP5c5xdiEeOGJGRns6h5B8w1QSNTbOZDwUEUCo9XR0dsQMA+Nqff1JWVAjnDfN5pr3973qmoaGhux+RhZnZ69evuzo7wT\/G1pljpoMDOvWKhdlvt27dYnMlF30GyaZsfNY9+1rsAADhphxaej0hQei7VVJQ2OXj0ysiBHZRfFycupoaXDBl8uQXPycH19TU+OzcicHSBftnn58f55JDKysruZXf3x\/fvHkTfadgHQnXm5En3IIoE\/GAwFgS+obVVFWfPn3a6wvb2trArt20cWNMTEz3ftDU2LjOzU3cjSmVFRVfsizxgQ7BE2NbGz8heKmTE+WdwjXCfTlP6B0RPVcYqLy8XOiyOtjUVzg7\/97fCvZg8IB7aUOwl9zWrhXr+b\/+mDHocjbWHor5+fqyoW2tKE++qakJfZsP09KE\/n6e0J+krJUBSk5OFr6piZpa8v37lC8YTCP4b1VV1RInJ\/Fl\/FLmhLOWwG7krhUkM3RoTk4OZRqsob6+BAAADKYI5QsQLj+Cn3M2wdi4vv8mh9++fYu8eHGli8s+X9\/8vDzYoU+Fho7R1RWH2wf7KEcBUFBQMHniRI4C4PixY5Q3eOL4cVF+gidiZJBSPYGYWk6dKnToN6H\/wcDV1dX8rC8wfuxsbMAka25uvnfv3qyZM1VVVJiCAXwPOOXRUVEcBUBdba2DnR0XpR98SMqoA2h+EZMjeSKucsvmzZTvQBRnYPmyZf09hZqaGvOf6aJ8n2H\/vn38v3\/48OHA\/v3ampoiWkR80TceP36bt\/enT584CgDYFFatXMk56Ye9lTLlU8RACzMAACl5\/fq1+JwBZSWld\/2MfQXr\/0hQUHePYse5c3v6BhXl5WB9WZiZqSgr00cC3I7ssGHKioomRkbr3NxiL19mT9Gj0IEgoa1QCXLqz6JwNNEp+RU7AIAnmJjQSQ8WOll6544d\/SUggBIAExCcPNgwAAy\/W1+lpaX3791zXrp0nKEhXAPq8vdDAxB6MKLAagKlYTV16tYtW64nJBQVFVGedXCCwEcMCgzklvTv8vGhvK+8vDxZJqJbPEZWjB7OKqIzAEYIiCMiElRTXQ1mT88Mon9agPzse1NcXMzfwhsbG9+8eXP79u2LFy4AZg7s2wd+7UF\/f3Czws+fv3njRkZ6OvxK95fAasG9AfuB6wCAOzp39iyHpN9syhR0q0O+Whs\/diwjP8djat0Ib1VEZ0Bm6FB\/f3+BTmHfvn076WfoQ1Feft6cOWDB\/\/5xAAnsjp2\/PWuQmPeFhYcPHVq2dKnb2rX3++lhwaGEiJjLl7ki\/aDM0b0e+OTp4cHULzIGABA12IYpl56RkSGE5tLU0KDMQu3pAFyJj++OAsH\/bFy\/HoylntfA7p6eng5b459Xr5b+N8cwPz8fMNNtKcFO856qFI7lZ2Hx8fFcqXWkLD0HunnzJoM\/ymPwu8AZoGM3305KEjRGCddvWL++urqa5lvPe\/t2oolJtxDPnT27ZxgHDJtlS5bwc7b5pw15PZ570q1b3Uen8K9ggH3gSA1AfwBIECEvC+eZF2yO1EZEWRmzo5l4zN7GiuXL6bwVIazSkerqEeHh3+hZI2C0pKWmggEza+ZM2M5v3bzZncgAAgGWmFKPrt8g7uADdH+28N07+KD+mDF6urrW06dHR0ezuQKYDrFzqGEvvp6QQMecY7zen8f4nVyKjqbzVnz37hVUCZibmf2eIYeg9ra2ivLyz1VVvf4ObvHC+fNhIwElAJbb5IkTe9b7A0I+f\/58584d8JjBb5aCQFBiYiLLpf\/okSN0boSy0y0rACAvK5ufl0fnftb0P7imPwwY6OmBpyF6WnJ7e\/vLly9BMzx8+JDrkX5KE0joQm08DB4tnRvJyswUR947Txy3NM7QkI4z0NnZOVPAkzzAwCoXl5zsbDLYQqCQAGul33HuXDqvEqxWMaX08cR0YzSdAfBHzU1NBc3EXr5sWX5+PhFuugC4coWd0g+vno5\/1djYKL6JjDzx3V5QYCCdN\/TlyxfQGILqARMjo2fPnpFpX3QAcJWVAABrlk62D5Cdra34lsET601GhIfTucPi4mJNDQ1BMaA\/Zsy1a9e4WKdCAGBibFxZWUln\/eLO5BMvAMBroRyy1I0BQfUAsIqyMthaubm5lBXTAxoALHOCwfJBlHmIEipkHQD4BxzoyUjdVFtbK6g\/0A2D7d7eb968ARiQScAsjwI52NvTzLDCk8HBw\/Ab8rKy\/CYOdHxiQTt7\/Rsh1dff7+eXl5fX0tJCYMBOACxcsICm25aSkoJnpA0Pz52rqajk0TscgAe0bMkS4VuqKCrOd3QMCgrKzMwElQJgEC5gCnLT1tYGmrqsrIzTUdd\/AICcFI2N3daupfkYQZkrKSjgWRUP2\/1rjBxJM6EN3tnWLVtETKsyNjJasnixn69vdFRUWlpaTk5O8adP\/EF3oGdaehD8pampCWS9qqqqoKAAkPMgOTk2JiYoMHC9l5e9nZ2FuTl3syFYAgB4oTQXLL6Qv4QBwG9xUfVbYkJ\/xFQZBzji8Lt\/WFqC\/oVNaMf27fv37TsSFBR84gTw8WPH\/A8cgD96eXqCPw0GmJmpqa62tkyP9qawG3H3tJgNAKCZ6QAE25CJsTHOtfEwP4sJJiZ1fY3H65OiIiPZoLsV5eU50RK9PwDExsZK8OnRDIX\/+FnhPtHEBPPyePifCBgnlG1+u+nxo0eCHhEQAPQCgKQKYkaoqYEvS3OdxcXFoKjxL5InkUejNXo0ZWO5bqqpqRHrWSAlK8jJcRsAMTH4H9qMadPojDvhEwgDf0b6QAEAPy6UlZlJ8wF1dXUFHDwoqXEPAICGhgYOm0DYAbBn927Kut5uys7OFrprDocBwBcsmmdk3eaQRCY+yMvJ0cxaIQBQHT6csqFlT3qYloYt4sk6APDPicFCpf+8wE\/Cbw7Jy8p+\/vyZOMGUbGVpWVpSQn9td+\/ckfhcex4bwix0WkB2U2dnp\/+BAzjnPsjJyHAaAHFYALB92zaBknNh42PDCDNWAIB\/UCJQ\/kJKSgo2c4gAAM2G+vpgyQi0qrNnzrBE8NgCgME\/h9HT95z40aF1bm4YVAGoaQKA\/p6Mn6+vQBnpbW1tG9avZ4\/UsQgAgsbO+JSVmTlBzKcn8JrpdGsaaD7ANCurAgHr8sBDYFuvdnYBgH96IlAYge8VnAoNVe7R6YRxAJQI4tuxDQDR0dGMh3rCw8MFTbmF16rKvtndrAMAn3127hS03LGyshKMKDGFqjgNAGYzSpY7O9Ms5uq5Q4GlxE5JYykAhIip8Sn98WOj8eMJAMQBAB1t7Xt37wq6AIkf5HMVAHxVezspSdAnDqrj2NGjivLyTC1j2JAhJcXFAxkAIPpnz5wRIif86dOnEk\/l4jAA+Oy9dWuH4CW\/VVVVu318GDllBAB8ot2al4UUHRUlSu8G+Lhw3TdOhoTgqeqScgDwy6iFG1JUV1t70N9fxFSToYMHF3K5QbRwAJhgYnL1ypWeUxfoU1NT0+JFizghWtwAAD8nOfjECYEOCnq+DzCKhD44AwD0N6aJExQRESHodpOUlCR0XfWtW7e0NTW5IlecAUD3tiRQf9ye1NraejosDMzZgQaA8+fP07xTWxsbgdITe1FZaem8OXO4JVEcAwCf17m50S8r+53AKQTTlgCgZ82nl6dnJu3s9D4pKDBQXlaWc7LESQDwywnCw8OFbtYAH0xLTQUg0Tk+GzJoUAHt8h0WUng\/AID7mungEBsbK+IoNNDJjIeeCQDoWatmZnSGtKLtoj+vXp3v6IiIV9AcBcshAOjp6h4+dEj0w42amhq3tWs5LULcBgDfPtmyebPoFVvV1dXgIfQ3x\/J1bi6HneDw8G5Tx8PdPT09nZHjhQsRERKs5CIA+A+PUlePi4tjRFwK3707sH+\/ro5OTw0gaIoeqwj82j27d6ekpDDSQbWzs\/PqlSsTsLdvIACgFb+7desWU30R8\/Pyzp0967xsmemUKaT5Lv+IPToqSqD4AQGAZEKlYNaTETIMUltb2\/lz54SIIBMASIzHGRrGXL4s3MEZoW5qbm4OCQ7G2auQAIBJHqOrCy5gBzFgBKeGhobAw4elwM0d0AD4lcyopXU6LIzINE0qKiravWsXs\/OoCQAkzxojR+7ds+cdl4+0xG3tXIiIsJkxY+CIxMACQDdPmTQpODiYu2W+zNL3799TU1PXuLpyMZGBAECkE7TZM2fGxMRI96BsBH348OHA\/v0cytwkABBXh0bXVauSk5OFy33nHDU1NUVFRtpYW5NXTwDQ20nYsX17dna29Ak9YDszM\/NIUJCDvb2sjAx51938f9J47hIu9Wl1AAAAAElFTkSuQmCC"
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
                    "value": "octocat.png",
                    "data": "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAAAAXNSR0IB2cksfwAAAAlwSFlzAAALEwAACxMBAJqcGAAAL+RJREFUeNrtXYlbTdv7P\/\/E19ScSqRJAypTg7poNGYKESEN5gwZCokylWQqKhq4EjLl3gplKFSoRDSnNGpU\/N7r+HW7qbX3OWefdfY+rfd5n\/vcJ\/ucs\/be72e9w3oH3uD\/\/Y8w4QHLPPIICBMAECZMAECYIR5naDjTwcF52TJPDw+fnTsDDh4MO3Xq8qVLN27cSE1Nffnixfv376urq3\/8PzU2NlZVVRUVFb158yYzM\/NhWtq9u3evJyTEXL58\/vz54ODgg\/7+q11dzc3M5GVlyeMlAGARg0SaTp680sXlUEBAwrVrIMHt7e0\/xEZdXV0fP34EeAAq3Netm2ZlpaKsTN4CAQA+\/sPScr2X18mQkOT794uLi3+wgCorK9NSU0+Hha1xddXR1ibviACASR4yaBDs8Tt37Lh75w7YKj9YT6AioqOi1q5ePUZXl7w+AgAhefzYsRs3bACrpqam5gdn6dOnT5eio93WrCFgIACgZm1NTdg4wfUsKy39IXUEBhs44m5r1+oRMBAA9GRlRUVPD4+nT5\/+GDCUm5u7zdt7hJoaefsDGgA21tawKTY3N\/8YkNTR3p6YmLhg\/vxhQ4YQAAwg1tTQ8N279\/379z8I\/aSqqqoTx48bjR9PACDlvGTx4uT794nE90eZmZlenp4KcnIEAFLFWqNHBwcH19bW4gy\/pKWm3rhxIyoyMiQ4+MD+\/Vu3bFnj6rpwwQLr6dMnmpjoaGkpKSjwlwe2uK6OjrGRkYW5ua2NjeO8ec7LloG3unnTpt27dh0KCLgSH5+Vmdna2opn8fV1dQf9\/dVUVQkAOM862trnz58X6+ks4AocaPAlwKxa6uQEwi07bJj4kOxgb79pw4ZToaHJyckAs66uLjHdV1NTU\/CJE6NHjSIA4CSP0dW9eOGCmEIoIT8zEWAvVx0+XOJ3am5q6uHuHhcXV15eLo77jQgPl+JjBCkEgIGe3qXo6G\/fvjEoBEVFRSAHy52dWR46HGtgAEY8mEyVlZUM3n5nZycAbIKJCQEA29MwY2Nj4W0xFRsBSYLNlaMJNkbjx2\/6eZjdM\/NUFPr+\/XtSUtJUCwsCADa+7KtXrjBiEDc2NkZHRYEzKk3pTDYzZoAGq2MoDJB4\/bq2piYBAFvOcc+eOSO66MM3\/PXXX6tdXaU45x68c6dFi64nJLS1tYn4uJqbm\/fs3i0zdCgBgCR5xfLlFRUVIr7Lgvz8vXv2aGpoDJzg93AlJXDiU1NTRdw4Ct+947qq5CoAdHV00lJTRQxfnjt71nLq1IGcDAKw3+Xjk5OTI8qTvPbnn9y1iDgJAD9fX1Fe2P1795Y6OZE8sJ4MG8HdO3eEfqStra27d+0iABA7W1lagtoV2sqHvWpgZrzQ5AkmJvFxcUKH0bhoEXEGAGoqKlGRkd+\/fxcujA3vdZyhIRFxmmeI4eHhQh+fnzl9Wnxn4QMUADOmTauqqhLiZXz79i3m8mUDPT0i1oLy6FGjgoODv379Ktxh+VgDAwIAZmLY+\/z8hFDKHR0dkRcvklJA0RXvQX9\/IfIIW1paVixfTgAgEo9QU0tJSRH00YPuBg1O+iMwyCrKyqfDwoTYhmJiYhTl5QkAhDR7hMjuSn\/8WH\/MGCKy4uApkyZlZWYKkUZlOnkyAYBgvGf3bkGz2Wpqata4uhIxFbdF6uHu\/uXLF0F1svfWrQQAdM0eQYu2vn\/\/Hh0VBdYqEVBsjkFEeLigp8j37t5lYZENuwBgZWkpqNkDGhaMJSKUEqhDMDPLfvVK0CZ206ysCAD6Zp+dOzs6OgRSrAEHD8rKyBBZlKBFtHnjxvr6eoEC06vZZKnyWPIcwYYRaC95+vQpVyLNUs86WloCdVUCkxVgQwDwi2WGDr2ekCDQFsLRtBMp5mFDhhw\/dkygc\/oD+\/cTAPxPTkZGIJe3pqaGWPysZcd58wSquTkVGgrKf+ACQElBIT09XSCzZ0Bl7XPUHBLorCA+Lm7o4MEDEQBqKiqvXr6k\/6SCg4MHcgc\/DjHYtPCy6JtDSUlJcpKLZEgGAOpqavl5efQb1CxetIgIFufMoYaGBrrn9+np3W3CpB8A2pqa9PtyFuTnk1xO7qZV0zeHwBxQl0TLGdwAGGdoSL\/7fkxMzIDqUymVnHj9Os3XDUYBfgzwMEs\/\/YErLAmTERadIy9epPnSX2RlYbaFeDjt\/tKSEpq1i6tJWpt08ZGgIJoYSEtNxdltBRMAANbZ2dk0ExzAfyISI328dcsWmqGh6wkJ2M4HcABg2JAhNFuYNDU1Tf\/jDyIr0sorXVxo5pCeO3tWegAQFxdH85R3ojS2XyXckxcuWECz3B6PEyh2AAQFBtK525KSEjK9cICw9fTpoOrpSIWnhwe3AbDey4tmEwGNkSOJZAyoWgKa\/SbE3cJMjABYtHAhTelXUVYmMjHQ2M7WlmZcyN7OjnsAsLK0pNOCuKKiQuqH8BDujxcvWkTHJ66vrxdfowOxAGCsgQGdKiG4hjQqHOAMVj5NM0FM3eaYB4CivDydVJ+O9nbQEkQCCB\/096fZcZEbAKBT3AiKjyR4Eu7mqMhIOhhwEoPMMAwA8NlZEt4izCEeOngwnbLYpqYmxp0BJgGgo61NJ7579MgR8so5zUMGDZKXlVUdPlxj1ChtLa0xOjrAWpqaqiK0ZpIZOpROugDjzgCPQRDTSf4GoDPyc8OVlEKCg\/Py8srKyiorKoo\/fXr58uXtpCSwFLds3jzTwUGd3fNMOccg8aPU1adaWLivWwcP+f69e69evSotKamrrW1uboaN7\/Pnz\/BHUcbI0kwYiwgPZyMA6Jz4MpXoBzuQ2ZQpJSUl3\/9L4Fp0dnbCy\/j48eOjhw9DT55c5eIyZfJkBTk5iRdfc3Snh0enNXr0nFmzfPfuTbh2DXYcEPT+2jc11Nf\/YWUlSo2vpoYGnb6LDPadZgYANjNmUCb6lZeVwbbNyM\/BWwEvgvIXAQ8tLS0F+fmHAgLs7eyUFRWJTNMXfTkZGaNx4zzWrYuNiQEFS7M19DZvbxGf8ywHB8o3C6+VqXEnDABATUWFcnoFyCKDQU89Xd2kW7cE6sQEmxaohe3bto01MODQ\/BKJ+KNgPTrY2x8JCoLNWNCRPMnJyePGjhVxDceOHqVTPsbIQFsGAACWH+Vy9+\/bx+BLmjVzZkFBgXADYwoLCyMiIvT19IhR9Puur6KsDBtwUlJSRUWFcJPCioqKFjg64vEnwQmUPAC2btlCudCMjAwGpQ2ezu5du1pbWoQeaQi7Wn19\/bVr18BXJnYR\/5GCg+u2di3oVfBoRZnA2d7e7n\/ggOg6VkdbmzKZACAqeiaBSAAA94gytxtug9luVlqamlevXPnBBIFCAF8Z1L0UT4enrFXSGDlynZvb0ydPhBtA+DvdvHlTj4lo\/XxHRzq90iQJADqHF\/NFVoi\/Z9K+ePHiB0P0jzaoq4uOijIzNR1o0q8oL79w\/nzY9YWbhNcfvX79ehpDZX1g5FD+nIe7u2QAYD19OuXizp45w\/hrW7VyJVioP5gmcPjiYmMN9PQY79QHXwgbrczQoXIyMqBqFOTkQPKUFBSUFBWVlZRUVVTA\/Bihqgr293BgJSVg+Ce4AC6D68GcgI8z67HAl1tZWsbHxdHvXUWfPn\/+7OXpycg64aFROgNgYogyG4UntOp8R+WG5uXliaN5f1BQUGNj4w8x0D8W0aNHG7y8dLS0hPAg+YIOUqs5evT4sWMtzM3tbW2dFi\/2WLdu5\/bthwICYDsAVfPn1at37txJSUl5\/OjRs6dPnz9\/npWVlfn8+bNnz9LT09PS0pKTkxMSEmIuX44IDz9+7Jjvnj2bNm50WbECdKn1jBmTJ04EDx5gA0ASAhtw\/UQTk7179rzIyhJoGgN9An1yKjSUwfQCSmcgKjISNwC8t25Fr6mtrW28yOGwPjkpKUnoUeZ0CFb+6tWr2bNmUZ7ZgeSBPMG+DoCZPXPmnt27L1+6BFZpfn5+SUlJbW1ta2srU4Y1378EUSgvK3v\/\/j0YgWBqBx4+vMLZ2XTyZHDGVIcPp3Q9Qck4zp2b9\/at0EOwaXa1efDgAYOK1H3dOsofnWphgQ8AoHEoc35gjxGH9IN58JI5BwB91HL27NleRfp8iVdXU7O1tt7m7X3+3Dl408XFxd\/Es5XSV1zVnz+DJgGTBvTMEicnEyMjsKnAfOpWDoANG2vrmJgYgaa5iOIGaGlqMvjeQV+hf\/HNmzfC9U4WBgAXIiLQq\/n48aOYDpt0tbU\/fPiAR7AAA2CiOC9bpjFypP6YMWDPgClyKToaDBW4webmZgZ3d6Yc+taWlrKystzc3BuJifv37YPFm02ZMn7cOE8Pj1cvX4JGwrMSUIDMBhWmTJpEqfZ9du7EAQBYCuWLn+XgIKbABext4GPhlCpwjsEiT01Nhb2TbRJPxxwHJzLl77+FGPUuCsHPzZk1i9lXH3bqFPpHAd5CBNx5jCujO7dviy9yZ2lhgW0bIySKu+K6ahXj1i9lnlxiYqJ4AbDa1ZXyznV1dMR3YEknU4oQG8h7yxbGA8oAKsa9YZ5AQdkSqu62QYGB4tv+YQGLFy0issUJ8vP1FYcf+OTJE\/Tv3r1zR1wAcFuzBv3blZWVivLyYq3JWLN6NZEtTtCxo0fFMdvB2MiI8vhi0oQJzANgyKBBlL0eGCxT6LcMwN2dyBYnKCQ4WFE8nf5PHD9O4Qlcv848AJyXLkX\/KugmceeuEABwiE6GhIhp1AVYGWBroMPBRuPGMQyAPORMu87OTtBNGADgQeNQkBAbKPjECfHZw16enuhfj42NZRIAjnPnon8vJiYGT132ahpxAEJsoKDAQPElmcvKyKATIru6umg2UKEFAPQ4a4E0DokCDRDau2ePWCcd+ezciV7AhYgIZgAwY9o0ZgNPotTs2dnaknMA9hNswJs2bhRr0SnYw\/V1dYg1dLS3a9PIR6IGQHJyMvpubWbMwFbDMdXcnE7TaUKSpdbW1lUrV4pbGAIOHkQvI+zUKVEBMNHEBP0bL1+8wFnEBLYW5lwgQkJQdXX1THt7cQuDmqoqOi8G\/nWUurpIAEhMTETfKuYet5oaGgX5+UTCWE4f3r8XUzVILz4ZEoJeif+BA8IDwEBPD\/3tIIuYy1jB8svIyCASxmYCJy0rKwtPuw2w8tGLKSoqEh4AlI3b17m54S\/lvnzpklgLmgiJSOCkxcfHY5MHyjH06MG7KAB8\/PgR8b0VFRU4J3p38y4fH8zZ7YQEorq6Ot+9e7HJg\/6YMeg5S+HIZrr9AmCqhQX6PoUrwBGd7Wxs3r17R+SMtVRYWMh4NYwovQnr6+oQean9AuBUaCj6PiU12hE8kzu3bxM5Yy3dvXNnrIEBTpFY7uyMXpLz0qWCAWDYkCHV1dWIbxQo4Y7hY\/Bhw\/x8fb99+0ZEjZ0nAP4HDghXny5Kjgy6txeiSrFvAIAKQ9\/nksWLJdjSzM7W9u3bt0TaWEjFxcUSmf528cIFxKo6OzvVVFUFAEDM5ctCG1UYIqHrvbzQCbGEJEVNTU0hISFCdBYTfUIFemHbt22jCwBKhQJok+D27zh37qtXr4iosZbKy8t99+6VE0NTQDSjg5bZr17RBcCK5cvRdwgWiKQa2I\/R0cnLyyP5cCyn2i9fXFeuxIwBytSgCf9tc9YvAG4nJaHwXVYmqdES4wwNoyIjifRzggoKCpY4OeH0hg319dFLOnH8ODUAwFdAFx0fP3ZMItKvpKAAilVMbXEJMU5dXV2PHj400NPDKSToNJn3799TA2Djhg3oG5s8caJEAOC6ahVlUxZCrCLQ1WGhoTjjJeu9vNBL+r11XG8A3L1zB\/H5\/Lw8iUi\/rrb28+fP0SfehNjpEM+eOZPxDln9sbKiIrpcxG3tWhQAYKHo+I+Yej5T3lVIcDAx\/TlKqSkpYJ1jk5bk+\/cRi\/m9WP4\/ADCdPFkIP1rckR\/HefOKi4uJJHGUGhoa9vn5YTOEdvn4IBZTVVWFAgB67EVdbS3+7X+UuvpfDx6Q7Z\/T9OnTJwszMzzBQ3NTU\/Rieg2W\/A8AEq9fR3xSIvk\/7m5uxPSXAnf47JkzzA4LRXRQrkNmy2\/etKlfAKA\/uWXzZszSP0JV9T7SpCPEFSp8927hggV4xAZdx9urhfq\/AADVgL6HiXgdAIDynFmzxDHGkBB+6ujoOB0WhudsePPGjWhLvmdUikczhorfAVBXU6Mzh5gQV6ggP9\/E2BhH6xCqrdy8x\/imfwEQFxdHX3Fg4IXz55MOKNJEzc3N\/vv34zkTqKqqQqxkt49PHwBAf2brli04pR905elTp7rEOQ6VEHZP+PuTjAzKRj2McExMDGIlycnJvQEwRlcXvXrMGRDjDA0\/FhURoZEyampqcpw7F4MScFu7FrGMr1+\/9gbAGuTwL8wOAGz\/y5ctI7F\/qaSgwEA1FRUMDdTQy+hWRL8AEHryJOLqGzdu4ASAxsiRF6mavRDiKD19+lSgEUZCM3qgka2NzX8AgO6zsM3bGycAplpYZD5\/TmRFKqm8vHy5szMGKboSH49Yxob16\/8DAHTDTZz9n\/nT+BpJ+F9KqaOj4+iRIxgKZdB9DU+Fhv4HAOg59HgOsbsdgOATJ4igSDHdTkoaI7Zh0t3ssmIFYg0PHjz4FwB6yBBQe3s7zu1fRVk56dYtIiVSTDnZ2TOmTRO3IJlNmYJYQ2lJyb8AmOXggLg0NzcXJwC0Ro\/OzckhUiLFVFlRAdszBlMCvQx+XgaPsgwS8xnwtD\/+KCsrI1IixdTY2HgoIACDLJWVliKWYW5m9gsAwcHBiOswV8GvcnGpr68nUiLF1NbWdvXKFQyylJqailjGalfXXwBIQvZB8fL0xNr9fOdO0v5fuqmrq+tJRgaG+pjz584hlhF4+PAvAKCHYNvb2WGT\/mFDhoQg1REh6aCCggIFOTlxi9M2b29K2\/4fAKB3XB1tbZzNf2KRaUyEpIOKP30aPWqUuMVp3pw5iDXwW5zwQL7ZEwNVV1N7QDWVlZAUUFVl5ThDQwzDYxBraGho+AcADvb2iIvy8DYCgl3hyZMnRD6knr7U1GDILx46eDDaFfkHACtdXBAXgX+MuQEWafw\/EAh2XytLSwwShe6TpayoyPNwd0dccSEiAicAxujqopP4CEkHNTU1zZg+HYNEoYsKdbS0eOheQN05Q9gm\/n369InIh9TT169fba2tMUhUYWEhYhkmxsa8vXv2IK44euQIZgAUEwAMAGpubsYzZeJFVhZiGX9YWvIOBQQgrjiwfz9OAOjp6n5CzvkgJDUmkDUWEwh9GDxn1iwe+uAJ8zBgcILJDOCBQI2NjegB7kzxjRs3EMtwXrqUd\/78ecQVmzZswAkAHW3tfOSxNCGpiQL9gSUKdCk6GrEMD3d3HnogpNuaNZhzobPJALwBQPX19Rbm5hgkKuzUKcQydmzfzkM3xHVetgzzQdhTchA2AOjLly94SuPRLu5Bf3\/e\/Xv3EFfMd3TE2g1XTS2ZpEIMAKqqqhprYIBBosCJRSwDHGDeo4cPEVfgTAXl10NeR2okQtJB5eXl2liGaXt5eiKWcfHCBV5WZibiCjzn1d2sKC8fFRlJ5EPqqbi4WE1VFYNErUZ2fIuJieG9efMGcQXmjogyQ4ceO3qUyIfU07t37+BdS3xuZER4OA99VGY5dSrmptC7d+3qJD1xpZq6uroyMzPxiNPOHTsQKwk9eZKHPiqb5eCAGQBgtLW2tBApkWLq6Oi4f+8eHnHav28fYiWBhw\/zbt68ibhiqZMTZgAscXKqq6sjUiLF1NraGh0VhUecjh45gliJn68v1UHYb4OFxc3Tp00rJ21RpJqampoO+vvjEafTYWGIlWzz9uadPXMGcYX31q2YAWCor49OYSXEdaqtrfX08MAjTpHINuOwDN6RoCDEFWBCYQaAmorKs2fPiJRIMRUVFTnOm4dHnK5euYJYyUoXF4p6gBPHj2MGgLKi4k1kBh8hrlNWVtZULIlAwLeRPa8WL1rEQ8+UDA8PxwwAORkZQB2REikm2OA0Ro7EI04pKSnoICcPfVR2JT4eMwCGDBoEmPz27RsRFKkkeLNnTp\/GcwoGjDanp1lZ8RYtXIi44u6dO5gBADzf0ZH0x5VWamhowBlZef36NWIxkydO5NnZ2iKuSH\/8GD8AJk2Y8PjRIyIrUkmlJSWzZ83CJkvorhCG+vo8c1NTxBU5OTn4ATByxIgLERFEVqSS0tPTjcePx+ZPohcDF\/DGGRoirqipqcEPAEV5+c2bNhFZkUo6e+YMbHB4BMl08mTESqqqqv7pDEeJEmVFRcwAGDp4sLmZGUmJk0oPeM3q1Rgm5PHZeelSxGIyMjJ+dYcuKSlBXIenfUVvK0hdnRyHSR+VlZVNNDHBJkXoM66Yy5d\/AeDBgweI67CdWvdk2WHDjgQFkWHx0kRdXV2PHj3CMBagmy9euIBYD7\/nFY+ycj44OBg\/AIAd58378uULkRupoZaWFsxtph6mpSHWs9LFhdaQPIkcBQBra2rmZGcTuZEm+8fc1BSnCKGH5E21sPgFAPRRwIcPHyQCAPDOd\/n4ELmRDgJr9vbt28OVlHCO20IvSUVZ+RcARo8ahbius7MTm9veKyfCdMoUYgVJB339+nWfnx+GwXjdbGJsjFhPXW3tv4OygWF9iKvx9DD6ncFhupGYSKRHCig3J8fyp8mBjdE5Pln\/X5TMo5MzhLk\/3H8qJBcvJrEgrhMYEX6+vpgPlNDl8N1Znjw6PUQxN0nv7Qrn5BAZ4jSVl5eDx4nT\/gGOjY1FLKl7VP0vAOzZvRtx9W28k8J6dQravWsXGZ3NXfr27Rtst\/Kyspglp6qqCrGqtatX\/wcAaIMJPIShgwdLCgN6urpZyOZFhNhMRUVF+LtLoQek9nRrfwFAU0MD\/QELXDVsfSqBFc7OLaRZEAepra0NjA2cp798dlu7lk4I6F8AAL8rKEB8ZrePj6QAwK+UT01J6erqIiLFLcrPyzPQ08MvMNFRUYhV3bp1qw8AoEfFJN+\/L0EAAM+ZPZtMT+Lc9r950yaJSAvYXYiF7di+vQ8ALHd2Zq0bAKykoHAkMJAoAa4QvKmMjIzRo0bhFxVKe75nRgav53AK9MemWVlJVgkY6utfu3aNyBYnqLCw0MbGRiJy4rpqFf2tnNfzk+hW6X6+vpIFAHjDNjNmgAdDxIvl1NjYuMvHR0FeXiJygq6nvXf3bs+LefQbKaakpEgWAPwMp4CAgIaGBiJkrCXYYqOjo\/FHfv6dDo\/0FXfv2tUvAJYsXoz2abC1c0Gw6vDhJ0NCOjo6iKixkDra2+Pj4vR0dSUlHpSWfK+hR7xebQnRXqaNtbXEATBk0KAJJiZX4uNJjhDbCN7Ig+RkMFMlGC\/xcHdHb+K91sbr9Xn0mF5sXa0pq+YnGBvn5uYSDLBK+isqKuxtbWWHDZOgbKB7If7111+9ru8NgJDgYMTnJdImqD+ePHFiTnY2wQBLpD8\/Lw\/\/NIlerDFyJFoe9vn5UQBgwfz56FudgLGqn1IP2NvZgc4lhwOSpc7OzkePHi1xcsKf8daLvbduRS91yqRJFACgdAPAAWWPEhg2ZAjc0rNnzwgGJCj9r16+tLO1lZORkbg8oMtaQEf9\/hHe73\/6+++\/Ed9SXV0tkQpJdM1AXFwcSZnGT62trcn377PEKNDR1kavts+DLJ6gs4WBFi5YwCoADBk0SE1V9XRYGImN4iTYcSIvXgQNjLnSpT\/23bsXvWBACC0AgCWHLhFOvH6dVQDo7iKx3svr\/fv3xC0WN4HBmZeXt83bm99YgSWcm5uLWPPTp0\/7\/BSvz79evnQJddjR0YFnzr0QRfT2traglBvq64mYiolgc4QnPH\/ePJw9TujkiaGXvWXzZgEAYG9nh\/66zRs3shAAv84CVVU9PTzKy8qIKmA81llYWAiWtERyPNF8+NAhtKfe35bN68+qRg\/rzcI16l5or2CsgcHZM2dKS0tJl2lGbB4Q\/bBTpyaamLAtBMLnjx8\/ItaPqGbh9fcPgYcPox+KsZERmzEArD5ixOJFi2JjYr7U1BAYCEdg7lZUVFyJj3davBjbZDtBeaqFBfouVru6CgwASqPq2NGjLAcAXxWAo7Z506aHaWlgvBKjSCD6\/Pnz3bt3vTw9tTQ1WRLq6ZPj4uIQd9HW1oY4oeMhvvf58+eI762pqRE05RUeourw4ROMjW2srefNmbNg\/nz4n8mTJmmNHg2KVayPmO8fJyYmVlZWkmgpmlpaWoo+fIiLjQVXEP94FCFOgdAzRa\/9+Sfi4ygAoEcIA+3csUOgwUe7fHxevXwJKrW1tRXMStiP4VlXVVXl5+dfv34d\/tXWxgYQIj4kKCooWE2dut3bG4zCT58+wd5AjpC7rfyGhoZ3795dvXJlg5eXuampmooK+zU8MHh66FtbtHChkAAAxxn91SDK9PN2pllZgdyj30FlRcXpsDALc3OxZhQCwEapqy9csACeXU5OTlNj40D2EGD7LCsre\/rkCXh9jvPmsTDCg56nCLsY4u5qe3RAERgAwIlUvWk3bdhAEwA2M2ZQ2B7fvwMGQBZhKwL9azx+PIb6GzkZmRnTp4cEB\/\/9998fP34EiIJASLerAHcHt1lXV5eXl3f50qUd27ZNNTeXeB6bOKKfP2gk8FMAwHr6dPQPFBcX0xRTsCb\/+usvxFeVlpb67t27ysUlIyMDYFBYWOjp4YEnuRzwOUJVFSDn4e5+OTr67Zs31dXVICXShATYXOpqawsKCm7fvh0UGLh0yRJDfX0wOCXb7ENEv66+rg5xy\/AGKU9seZQ\/k\/74MfrJ0s8CNxo\/\/uWLF\/1JFcCDH2gDQUxLTeVrZ9ii4I+YQxCgFkyMjZ0WLwYnJzIy8tHDh6UlJaBMv379CkqM\/aiA7aOpqamqsvLDhw+ZmZkJCQmHAgJgZwElPNbAQLIFKwyyz86d6OdwKjSU8kuoATB39mz0z8BWTXMXgcumT5t27969Pm2hysrKgICAiSYm9nZ2Dx8+7I5hXY2Pl1TGFcjKqJEjxxoa\/mFpuXzZMrAWToaExMbE3Lt799mzZ+AyopOmMJvyOdnZSbduRUVGBp84sWvnTteVKx3s7EyMjHS1tWGnZ+cBligtQsAFRT8QbU1NBgAADNs2+umvWL5coKr2o0eO1PbV3QTUNNzV58+fewZn+NVGppMns0RZwzKUFBQ0NTRcV6368P49e06sQk+eBFmXmg0eze7r1qEfCNgOdL6HFgCcFi1C\/9jbt28FLWSxsbb+68EDRPgF\/un5s2eRFy+WlJQABl6\/fj1v7lyWYADU0ZxZs15Q7QuYCfza0NBQCfYjwfn8we5AO\/pG48YxBgD4PRBxUaKtfe6j4ISBlVZeXt6nVQ1u6JzZs8E3ne\/omJubCzoBHAOwoFiSaPT40SO2HajBY6ypqfF0d+doSIc+r3NzQz+KJNoTLXg0r1vp4oL+yXcFBUJYmWBLeG\/dChjo8xzewsyMb+1t+nkkBwKXnJws8R1uuJIS4Ja1rnBBQUGv1jdSxvD8KUcnTqU9j4xHf8NGKx0g4cYgwzebGBvDl\/cSKf5gcf0xY0DiFy1Y0P1H8B9GSK4aAdDo5eGBPnyRuB7IzcnR0dKSVgCAq4N+AumPH9P\/Nh6DbkdTU5PW6NHCYWDZ0qXZr171wgA48g8fPgw7daqnF15WVrZq5UpJOQPGRkYpyJppNlB7e7tAWSocYnj+lMf2jvPmiQUAsPkVFxejf\/vPq1eF3lldV63q0xb6fYd78OCBRMYuAOr8\/PwaGxvZf+yVk52tMny49AHgyZMnzMZjeAJdvXnTJspHbz19upAYGDbMeelSRL4Q+ACgZGADgGvOnT2LXwmMHjXqPWvinpRKYMf27dw95e2TQTwob9zB3l6MAJAdNgxdesP3hoUORcvLygafONGnjmtvazsTFvaHldWFiIj6+vovNTVWU6fiPB0DF3+1qyuHskcfP348Sl1daqRfTkamrLQUfctCjDPlCfqBWQ4OlI++VwdqgRjeWZ8pQxUVFfxR4\/Jycgf27wf3IPP5c5xdiEeOGJGRns6h5B8w1QSNTbOZDwUEUCo9XR0dsQMA+Nqff1JWVAjnDfN5pr3973qmoaGhux+RhZnZ69evuzo7wT\/G1pljpoMDOvWKhdlvt27dYnMlF30GyaZsfNY9+1rsAADhphxaej0hQei7VVJQ2OXj0ysiBHZRfFycupoaXDBl8uQXPycH19TU+OzcicHSBftnn58f55JDKysruZXf3x\/fvHkTfadgHQnXm5En3IIoE\/GAwFgS+obVVFWfPn3a6wvb2trArt20cWNMTEz3ftDU2LjOzU3cjSmVFRVfsizxgQ7BE2NbGz8heKmTE+WdwjXCfTlP6B0RPVcYqLy8XOiyOtjUVzg7\/97fCvZg8IB7aUOwl9zWrhXr+b\/+mDHocjbWHor5+fqyoW2tKE++qakJfZsP09KE\/n6e0J+krJUBSk5OFr6piZpa8v37lC8YTCP4b1VV1RInJ\/Fl\/FLmhLOWwG7krhUkM3RoTk4OZRqsob6+BAAADKYI5QsQLj+Cn3M2wdi4vv8mh9++fYu8eHGli8s+X9\/8vDzYoU+Fho7R1RWH2wf7KEcBUFBQMHniRI4C4PixY5Q3eOL4cVF+gidiZJBSPYGYWk6dKnToN6H\/wcDV1dX8rC8wfuxsbMAka25uvnfv3qyZM1VVVJiCAXwPOOXRUVEcBUBdba2DnR0XpR98SMqoA2h+EZMjeSKucsvmzZTvQBRnYPmyZf09hZqaGvOf6aJ8n2H\/vn38v3\/48OHA\/v3ampoiWkR80TceP36bt\/enT584CgDYFFatXMk56Ye9lTLlU8RACzMAACl5\/fq1+JwBZSWld\/2MfQXr\/0hQUHePYse5c3v6BhXl5WB9WZiZqSgr00cC3I7ssGHKioomRkbr3NxiL19mT9Gj0IEgoa1QCXLqz6JwNNEp+RU7AIAnmJjQSQ8WOll6544d\/SUggBIAExCcPNgwAAy\/W1+lpaX3791zXrp0nKEhXAPq8vdDAxB6MKLAagKlYTV16tYtW64nJBQVFVGedXCCwEcMCgzklvTv8vGhvK+8vDxZJqJbPEZWjB7OKqIzAEYIiCMiElRTXQ1mT88Mon9agPzse1NcXMzfwhsbG9+8eXP79u2LFy4AZg7s2wd+7UF\/f3Czws+fv3njRkZ6OvxK95fAasG9AfuB6wCAOzp39iyHpN9syhR0q0O+Whs\/diwjP8djat0Ib1VEZ0Bm6FB\/f3+BTmHfvn076WfoQ1Feft6cOWDB\/\/5xAAnsjp2\/PWuQmPeFhYcPHVq2dKnb2rX3++lhwaGEiJjLl7ki\/aDM0b0e+OTp4cHULzIGABA12IYpl56RkSGE5tLU0KDMQu3pAFyJj++OAsH\/bFy\/HoylntfA7p6eng5b459Xr5b+N8cwPz8fMNNtKcFO856qFI7lZ2Hx8fFcqXWkLD0HunnzJoM\/ymPwu8AZoGM3305KEjRGCddvWL++urqa5lvPe\/t2oolJtxDPnT27ZxgHDJtlS5bwc7b5pw15PZ570q1b3Uen8K9ggH3gSA1AfwBIECEvC+eZF2yO1EZEWRmzo5l4zN7GiuXL6bwVIazSkerqEeHh3+hZI2C0pKWmggEza+ZM2M5v3bzZncgAAgGWmFKPrt8g7uADdH+28N07+KD+mDF6urrW06dHR0ezuQKYDrFzqGEvvp6QQMecY7zen8f4nVyKjqbzVnz37hVUCZibmf2eIYeg9ra2ivLyz1VVvf4ObvHC+fNhIwElAJbb5IkTe9b7A0I+f\/58584d8JjBb5aCQFBiYiLLpf\/okSN0boSy0y0rACAvK5ufl0fnftb0P7imPwwY6OmBpyF6WnJ7e\/vLly9BMzx8+JDrkX5KE0joQm08DB4tnRvJyswUR947Txy3NM7QkI4z0NnZOVPAkzzAwCoXl5zsbDLYQqCQAGul33HuXDqvEqxWMaX08cR0YzSdAfBHzU1NBc3EXr5sWX5+PhFuugC4coWd0g+vno5\/1djYKL6JjDzx3V5QYCCdN\/TlyxfQGILqARMjo2fPnpFpX3QAcJWVAABrlk62D5Cdra34lsET601GhIfTucPi4mJNDQ1BMaA\/Zsy1a9e4WKdCAGBibFxZWUln\/eLO5BMvAMBroRyy1I0BQfUAsIqyMthaubm5lBXTAxoALHOCwfJBlHmIEipkHQD4BxzoyUjdVFtbK6g\/0A2D7d7eb968ARiQScAsjwI52NvTzLDCk8HBw\/Ab8rKy\/CYOdHxiQTt7\/Rsh1dff7+eXl5fX0tJCYMBOACxcsICm25aSkoJnpA0Pz52rqajk0TscgAe0bMkS4VuqKCrOd3QMCgrKzMwElQJgEC5gCnLT1tYGmrqsrIzTUdd\/AICcFI2N3daupfkYQZkrKSjgWRUP2\/1rjBxJM6EN3tnWLVtETKsyNjJasnixn69vdFRUWlpaTk5O8adP\/EF3oGdaehD8pampCWS9qqqqoKAAkPMgOTk2JiYoMHC9l5e9nZ2FuTl3syFYAgB4oTQXLL6Qv4QBwG9xUfVbYkJ\/xFQZBzji8Lt\/WFqC\/oVNaMf27fv37TsSFBR84gTw8WPH\/A8cgD96eXqCPw0GmJmpqa62tkyP9qawG3H3tJgNAKCZ6QAE25CJsTHOtfEwP4sJJiZ1fY3H65OiIiPZoLsV5eU50RK9PwDExsZK8OnRDIX\/+FnhPtHEBPPyePifCBgnlG1+u+nxo0eCHhEQAPQCgKQKYkaoqYEvS3OdxcXFoKjxL5InkUejNXo0ZWO5bqqpqRHrWSAlK8jJcRsAMTH4H9qMadPojDvhEwgDf0b6QAEAPy6UlZlJ8wF1dXUFHDwoqXEPAICGhgYOm0DYAbBn927Kut5uys7OFrprDocBwBcsmmdk3eaQRCY+yMvJ0cxaIQBQHT6csqFlT3qYloYt4sk6APDPicFCpf+8wE\/Cbw7Jy8p+\/vyZOMGUbGVpWVpSQn9td+\/ckfhcex4bwix0WkB2U2dnp\/+BAzjnPsjJyHAaAHFYALB92zaBknNh42PDCDNWAIB\/UCJQ\/kJKSgo2c4gAAM2G+vpgyQi0qrNnzrBE8NgCgME\/h9HT95z40aF1bm4YVAGoaQKA\/p6Mn6+vQBnpbW1tG9avZ4\/UsQgAgsbO+JSVmTlBzKcn8JrpdGsaaD7ANCurAgHr8sBDYFuvdnYBgH96IlAYge8VnAoNVe7R6YRxAJQI4tuxDQDR0dGMh3rCw8MFTbmF16rKvtndrAMAn3127hS03LGyshKMKDGFqjgNAGYzSpY7O9Ms5uq5Q4GlxE5JYykAhIip8Sn98WOj8eMJAMQBAB1t7Xt37wq6AIkf5HMVAHxVezspSdAnDqrj2NGjivLyTC1j2JAhJcXFAxkAIPpnz5wRIif86dOnEk\/l4jAA+Oy9dWuH4CW\/VVVVu318GDllBAB8ot2al4UUHRUlSu8G+Lhw3TdOhoTgqeqScgDwy6iFG1JUV1t70N9fxFSToYMHF3K5QbRwAJhgYnL1ypWeUxfoU1NT0+JFizghWtwAAD8nOfjECYEOCnq+DzCKhD44AwD0N6aJExQRESHodpOUlCR0XfWtW7e0NTW5IlecAUD3tiRQf9ye1NraejosDMzZgQaA8+fP07xTWxsbgdITe1FZaem8OXO4JVEcAwCf17m50S8r+53AKQTTlgCgZ82nl6dnJu3s9D4pKDBQXlaWc7LESQDwywnCw8OFbtYAH0xLTQUg0Tk+GzJoUAHt8h0WUng\/AID7mungEBsbK+IoNNDJjIeeCQDoWatmZnSGtKLtoj+vXp3v6IiIV9AcBcshAOjp6h4+dEj0w42amhq3tWs5LULcBgDfPtmyebPoFVvV1dXgIfQ3x\/J1bi6HneDw8G5Tx8PdPT09nZHjhQsRERKs5CIA+A+PUlePi4tjRFwK3707sH+\/ro5OTw0gaIoeqwj82j27d6ekpDDSQbWzs\/PqlSsTsLdvIACgFb+7desWU30R8\/Pyzp0967xsmemUKaT5Lv+IPToqSqD4AQGAZEKlYNaTETIMUltb2\/lz54SIIBMASIzHGRrGXL4s3MEZoW5qbm4OCQ7G2auQAIBJHqOrCy5gBzFgBKeGhobAw4elwM0d0AD4lcyopXU6LIzINE0qKiravWsXs\/OoCQAkzxojR+7ds+cdl4+0xG3tXIiIsJkxY+CIxMACQDdPmTQpODiYu2W+zNL3799TU1PXuLpyMZGBAECkE7TZM2fGxMRI96BsBH348OHA\/v0cytwkABBXh0bXVauSk5OFy33nHDU1NUVFRtpYW5NXTwDQ20nYsX17dna29Ak9YDszM\/NIUJCDvb2sjAx51938f9J47hIu9Wl1AAAAAElFTkSuQmCC"
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
                    "value": "octocat.png",
                    "data": "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAAAAXNSR0IB2cksfwAAAAlwSFlzAAALEwAACxMBAJqcGAAAL+RJREFUeNrtXYlbTdv7P\/\/E19ScSqRJAypTg7poNGYKESEN5gwZCokylWQqKhq4EjLl3gplKFSoRDSnNGpU\/N7r+HW7qbX3OWefdfY+rfd5n\/vcJ\/ucs\/be72e9w3oH3uD\/\/Y8w4QHLPPIICBMAECZMAECYIR5naDjTwcF52TJPDw+fnTsDDh4MO3Xq8qVLN27cSE1Nffnixfv376urq3\/8PzU2NlZVVRUVFb158yYzM\/NhWtq9u3evJyTEXL58\/vz54ODgg\/7+q11dzc3M5GVlyeMlAGARg0SaTp680sXlUEBAwrVrIMHt7e0\/xEZdXV0fP34EeAAq3Netm2ZlpaKsTN4CAQA+\/sPScr2X18mQkOT794uLi3+wgCorK9NSU0+Hha1xddXR1ibviACASR4yaBDs8Tt37Lh75w7YKj9YT6AioqOi1q5ePUZXl7w+AgAhefzYsRs3bACrpqam5gdn6dOnT5eio93WrCFgIACgZm1NTdg4wfUsKy39IXUEBhs44m5r1+oRMBAA9GRlRUVPD4+nT5\/+GDCUm5u7zdt7hJoaefsDGgA21tawKTY3N\/8YkNTR3p6YmLhg\/vxhQ4YQAAwg1tTQ8N279\/379z8I\/aSqqqoTx48bjR9PACDlvGTx4uT794nE90eZmZlenp4KcnIEAFLFWqNHBwcH19bW4gy\/pKWm3rhxIyoyMiQ4+MD+\/Vu3bFnj6rpwwQLr6dMnmpjoaGkpKSjwlwe2uK6OjrGRkYW5ua2NjeO8ec7LloG3unnTpt27dh0KCLgSH5+Vmdna2opn8fV1dQf9\/dVUVQkAOM862trnz58X6+ks4AocaPAlwKxa6uQEwi07bJj4kOxgb79pw4ZToaHJyckAs66uLjHdV1NTU\/CJE6NHjSIA4CSP0dW9eOGCmEIoIT8zEWAvVx0+XOJ3am5q6uHuHhcXV15eLo77jQgPl+JjBCkEgIGe3qXo6G\/fvjEoBEVFRSAHy52dWR46HGtgAEY8mEyVlZUM3n5nZycAbIKJCQEA29MwY2Nj4W0xFRsBSYLNlaMJNkbjx2\/6eZjdM\/NUFPr+\/XtSUtJUCwsCADa+7KtXrjBiEDc2NkZHRYEzKk3pTDYzZoAGq2MoDJB4\/bq2piYBAFvOcc+eOSO66MM3\/PXXX6tdXaU45x68c6dFi64nJLS1tYn4uJqbm\/fs3i0zdCgBgCR5xfLlFRUVIr7Lgvz8vXv2aGpoDJzg93AlJXDiU1NTRdw4Ct+947qq5CoAdHV00lJTRQxfnjt71nLq1IGcDAKw3+Xjk5OTI8qTvPbnn9y1iDgJAD9fX1Fe2P1795Y6OZE8sJ4MG8HdO3eEfqStra27d+0iABA7W1lagtoV2sqHvWpgZrzQ5AkmJvFxcUKH0bhoEXEGAGoqKlGRkd+\/fxcujA3vdZyhIRFxmmeI4eHhQh+fnzl9Wnxn4QMUADOmTauqqhLiZXz79i3m8mUDPT0i1oLy6FGjgoODv379Ktxh+VgDAwIAZmLY+\/z8hFDKHR0dkRcvklJA0RXvQX9\/IfIIW1paVixfTgAgEo9QU0tJSRH00YPuBg1O+iMwyCrKyqfDwoTYhmJiYhTl5QkAhDR7hMjuSn\/8WH\/MGCKy4uApkyZlZWYKkUZlOnkyAYBgvGf3bkGz2Wpqata4uhIxFbdF6uHu\/uXLF0F1svfWrQQAdM0eQYu2vn\/\/Hh0VBdYqEVBsjkFEeLigp8j37t5lYZENuwBgZWkpqNkDGhaMJSKUEqhDMDPLfvVK0CZ206ysCAD6Zp+dOzs6OgRSrAEHD8rKyBBZlKBFtHnjxvr6eoEC06vZZKnyWPIcwYYRaC95+vQpVyLNUs86WloCdVUCkxVgQwDwi2WGDr2ekCDQFsLRtBMp5mFDhhw\/dkygc\/oD+\/cTAPxPTkZGIJe3pqaGWPysZcd58wSquTkVGgrKf+ACQElBIT09XSCzZ0Bl7XPUHBLorCA+Lm7o4MEDEQBqKiqvXr6k\/6SCg4MHcgc\/DjHYtPCy6JtDSUlJcpKLZEgGAOpqavl5efQb1CxetIgIFufMoYaGBrrn9+np3W3CpB8A2pqa9PtyFuTnk1xO7qZV0zeHwBxQl0TLGdwAGGdoSL\/7fkxMzIDqUymVnHj9Os3XDUYBfgzwMEs\/\/YErLAmTERadIy9epPnSX2RlYbaFeDjt\/tKSEpq1i6tJWpt08ZGgIJoYSEtNxdltBRMAANbZ2dk0ExzAfyISI328dcsWmqGh6wkJ2M4HcABg2JAhNFuYNDU1Tf\/jDyIr0sorXVxo5pCeO3tWegAQFxdH85R3ojS2XyXckxcuWECz3B6PEyh2AAQFBtK525KSEjK9cICw9fTpoOrpSIWnhwe3AbDey4tmEwGNkSOJZAyoWgKa\/SbE3cJMjABYtHAhTelXUVYmMjHQ2M7WlmZcyN7OjnsAsLK0pNOCuKKiQuqH8BDujxcvWkTHJ66vrxdfowOxAGCsgQGdKiG4hjQqHOAMVj5NM0FM3eaYB4CivDydVJ+O9nbQEkQCCB\/096fZcZEbAKBT3AiKjyR4Eu7mqMhIOhhwEoPMMAwA8NlZEt4izCEeOngwnbLYpqYmxp0BJgGgo61NJ7579MgR8so5zUMGDZKXlVUdPlxj1ChtLa0xOjrAWpqaqiK0ZpIZOpROugDjzgCPQRDTSf4GoDPyc8OVlEKCg\/Py8srKyiorKoo\/fXr58uXtpCSwFLds3jzTwUGd3fNMOccg8aPU1adaWLivWwcP+f69e69evSotKamrrW1uboaN7\/Pnz\/BHUcbI0kwYiwgPZyMA6Jz4MpXoBzuQ2ZQpJSUl3\/9L4Fp0dnbCy\/j48eOjhw9DT55c5eIyZfJkBTk5iRdfc3Snh0enNXr0nFmzfPfuTbh2DXYcEPT+2jc11Nf\/YWUlSo2vpoYGnb6LDPadZgYANjNmUCb6lZeVwbbNyM\/BWwEvgvIXAQ8tLS0F+fmHAgLs7eyUFRWJTNMXfTkZGaNx4zzWrYuNiQEFS7M19DZvbxGf8ywHB8o3C6+VqXEnDABATUWFcnoFyCKDQU89Xd2kW7cE6sQEmxaohe3bto01MODQ\/BKJ+KNgPTrY2x8JCoLNWNCRPMnJyePGjhVxDceOHqVTPsbIQFsGAACWH+Vy9+\/bx+BLmjVzZkFBgXADYwoLCyMiIvT19IhR9Puur6KsDBtwUlJSRUWFcJPCioqKFjg64vEnwQmUPAC2btlCudCMjAwGpQ2ezu5du1pbWoQeaQi7Wn19\/bVr18BXJnYR\/5GCg+u2di3oVfBoRZnA2d7e7n\/ggOg6VkdbmzKZACAqeiaBSAAA94gytxtug9luVlqamlevXPnBBIFCAF8Z1L0UT4enrFXSGDlynZvb0ydPhBtA+DvdvHlTj4lo\/XxHRzq90iQJADqHF\/NFVoi\/Z9K+ePHiB0P0jzaoq4uOijIzNR1o0q8oL79w\/nzY9YWbhNcfvX79ehpDZX1g5FD+nIe7u2QAYD19OuXizp45w\/hrW7VyJVioP5gmcPjiYmMN9PQY79QHXwgbrczQoXIyMqBqFOTkQPKUFBSUFBWVlZRUVVTA\/Bihqgr293BgJSVg+Ce4AC6D68GcgI8z67HAl1tZWsbHxdHvXUWfPn\/+7OXpycg64aFROgNgYogyG4UntOp8R+WG5uXliaN5f1BQUGNj4w8x0D8W0aNHG7y8dLS0hPAg+YIOUqs5evT4sWMtzM3tbW2dFi\/2WLdu5\/bthwICYDsAVfPn1at37txJSUl5\/OjRs6dPnz9\/npWVlfn8+bNnz9LT09PS0pKTkxMSEmIuX44IDz9+7Jjvnj2bNm50WbECdKn1jBmTJ04EDx5gA0ASAhtw\/UQTk7179rzIyhJoGgN9An1yKjSUwfQCSmcgKjISNwC8t25Fr6mtrW28yOGwPjkpKUnoUeZ0CFb+6tWr2bNmUZ7ZgeSBPMG+DoCZPXPmnt27L1+6BFZpfn5+SUlJbW1ta2srU4Y1378EUSgvK3v\/\/j0YgWBqBx4+vMLZ2XTyZHDGVIcPp3Q9Qck4zp2b9\/at0EOwaXa1efDgAYOK1H3dOsofnWphgQ8AoHEoc35gjxGH9IN58JI5BwB91HL27NleRfp8iVdXU7O1tt7m7X3+3Dl408XFxd\/Es5XSV1zVnz+DJgGTBvTMEicnEyMjsKnAfOpWDoANG2vrmJgYgaa5iOIGaGlqMvjeQV+hf\/HNmzfC9U4WBgAXIiLQq\/n48aOYDpt0tbU\/fPiAR7AAA2CiOC9bpjFypP6YMWDPgClyKToaDBW4webmZgZ3d6Yc+taWlrKystzc3BuJifv37YPFm02ZMn7cOE8Pj1cvX4JGwrMSUIDMBhWmTJpEqfZ9du7EAQBYCuWLn+XgIKbABext4GPhlCpwjsEiT01Nhb2TbRJPxxwHJzLl77+FGPUuCsHPzZk1i9lXH3bqFPpHAd5CBNx5jCujO7dviy9yZ2lhgW0bIySKu+K6ahXj1i9lnlxiYqJ4AbDa1ZXyznV1dMR3YEknU4oQG8h7yxbGA8oAKsa9YZ5AQdkSqu62QYGB4tv+YQGLFy0issUJ8vP1FYcf+OTJE\/Tv3r1zR1wAcFuzBv3blZWVivLyYq3JWLN6NZEtTtCxo0fFMdvB2MiI8vhi0oQJzANgyKBBlL0eGCxT6LcMwN2dyBYnKCQ4WFE8nf5PHD9O4Qlcv848AJyXLkX\/KugmceeuEABwiE6GhIhp1AVYGWBroMPBRuPGMQyAPORMu87OTtBNGADgQeNQkBAbKPjECfHZw16enuhfj42NZRIAjnPnon8vJiYGT132ahpxAEJsoKDAQPElmcvKyKATIru6umg2UKEFAPQ4a4E0DokCDRDau2ePWCcd+ezciV7AhYgIZgAwY9o0ZgNPotTs2dnaknMA9hNswJs2bhRr0SnYw\/V1dYg1dLS3a9PIR6IGQHJyMvpubWbMwFbDMdXcnE7TaUKSpdbW1lUrV4pbGAIOHkQvI+zUKVEBMNHEBP0bL1+8wFnEBLYW5lwgQkJQdXX1THt7cQuDmqoqOi8G\/nWUurpIAEhMTETfKuYet5oaGgX5+UTCWE4f3r8XUzVILz4ZEoJeif+BA8IDwEBPD\/3tIIuYy1jB8svIyCASxmYCJy0rKwtPuw2w8tGLKSoqEh4AlI3b17m54S\/lvnzpklgLmgiJSOCkxcfHY5MHyjH06MG7KAB8\/PgR8b0VFRU4J3p38y4fH8zZ7YQEorq6Ot+9e7HJg\/6YMeg5S+HIZrr9AmCqhQX6PoUrwBGd7Wxs3r17R+SMtVRYWMh4NYwovQnr6+oQean9AuBUaCj6PiU12hE8kzu3bxM5Yy3dvXNnrIEBTpFY7uyMXpLz0qWCAWDYkCHV1dWIbxQo4Y7hY\/Bhw\/x8fb99+0ZEjZ0nAP4HDghXny5Kjgy6txeiSrFvAIAKQ9\/nksWLJdjSzM7W9u3bt0TaWEjFxcUSmf528cIFxKo6OzvVVFUFAEDM5ctCG1UYIqHrvbzQCbGEJEVNTU0hISFCdBYTfUIFemHbt22jCwBKhQJok+D27zh37qtXr4iosZbKy8t99+6VE0NTQDSjg5bZr17RBcCK5cvRdwgWiKQa2I\/R0cnLyyP5cCyn2i9fXFeuxIwBytSgCf9tc9YvAG4nJaHwXVYmqdES4wwNoyIjifRzggoKCpY4OeH0hg319dFLOnH8ODUAwFdAFx0fP3ZMItKvpKAAilVMbXEJMU5dXV2PHj400NPDKSToNJn3799TA2Djhg3oG5s8caJEAOC6ahVlUxZCrCLQ1WGhoTjjJeu9vNBL+r11XG8A3L1zB\/H5\/Lw8iUi\/rrb28+fP0SfehNjpEM+eOZPxDln9sbKiIrpcxG3tWhQAYKHo+I+Yej5T3lVIcDAx\/TlKqSkpYJ1jk5bk+\/cRi\/m9WP4\/ADCdPFkIP1rckR\/HefOKi4uJJHGUGhoa9vn5YTOEdvn4IBZTVVWFAgB67EVdbS3+7X+UuvpfDx6Q7Z\/T9OnTJwszMzzBQ3NTU\/Rieg2W\/A8AEq9fR3xSIvk\/7m5uxPSXAnf47JkzzA4LRXRQrkNmy2\/etKlfAKA\/uWXzZszSP0JV9T7SpCPEFSp8927hggV4xAZdx9urhfq\/AADVgL6HiXgdAIDynFmzxDHGkBB+6ujoOB0WhudsePPGjWhLvmdUikczhorfAVBXU6Mzh5gQV6ggP9\/E2BhH6xCqrdy8x\/imfwEQFxdHX3Fg4IXz55MOKNJEzc3N\/vv34zkTqKqqQqxkt49PHwBAf2brli04pR905elTp7rEOQ6VEHZP+PuTjAzKRj2McExMDGIlycnJvQEwRlcXvXrMGRDjDA0\/FhURoZEyampqcpw7F4MScFu7FrGMr1+\/9gbAGuTwL8wOAGz\/y5ctI7F\/qaSgwEA1FRUMDdTQy+hWRL8AEHryJOLqGzdu4ASAxsiRF6mavRDiKD19+lSgEUZCM3qgka2NzX8AgO6zsM3bGycAplpYZD5\/TmRFKqm8vHy5szMGKboSH49Yxob16\/8DAHTDTZz9n\/nT+BpJ+F9KqaOj4+iRIxgKZdB9DU+Fhv4HAOg59HgOsbsdgOATJ4igSDHdTkoaI7Zh0t3ssmIFYg0PHjz4FwB6yBBQe3s7zu1fRVk56dYtIiVSTDnZ2TOmTRO3IJlNmYJYQ2lJyb8AmOXggLg0NzcXJwC0Ro\/OzckhUiLFVFlRAdszBlMCvQx+XgaPsgwS8xnwtD\/+KCsrI1IixdTY2HgoIACDLJWVliKWYW5m9gsAwcHBiOswV8GvcnGpr68nUiLF1NbWdvXKFQyylJqailjGalfXXwBIQvZB8fL0xNr9fOdO0v5fuqmrq+tJRgaG+pjz584hlhF4+PAvAKCHYNvb2WGT\/mFDhoQg1REh6aCCggIFOTlxi9M2b29K2\/4fAKB3XB1tbZzNf2KRaUyEpIOKP30aPWqUuMVp3pw5iDXwW5zwQL7ZEwNVV1N7QDWVlZAUUFVl5ThDQwzDYxBraGho+AcADvb2iIvy8DYCgl3hyZMnRD6knr7U1GDILx46eDDaFfkHACtdXBAXgX+MuQEWafw\/EAh2XytLSwwShe6TpayoyPNwd0dccSEiAicAxujqopP4CEkHNTU1zZg+HYNEoYsKdbS0eOheQN05Q9gm\/n369InIh9TT169fba2tMUhUYWEhYhkmxsa8vXv2IK44euQIZgAUEwAMAGpubsYzZeJFVhZiGX9YWvIOBQQgrjiwfz9OAOjp6n5CzvkgJDUmkDUWEwh9GDxn1iwe+uAJ8zBgcILJDOCBQI2NjegB7kzxjRs3EMtwXrqUd\/78ecQVmzZswAkAHW3tfOSxNCGpiQL9gSUKdCk6GrEMD3d3HnogpNuaNZhzobPJALwBQPX19Rbm5hgkKuzUKcQydmzfzkM3xHVetgzzQdhTchA2AOjLly94SuPRLu5Bf3\/e\/Xv3EFfMd3TE2g1XTS2ZpEIMAKqqqhprYIBBosCJRSwDHGDeo4cPEVfgTAXl10NeR2okQtJB5eXl2liGaXt5eiKWcfHCBV5WZibiCjzn1d2sKC8fFRlJ5EPqqbi4WE1VFYNErUZ2fIuJieG9efMGcQXmjogyQ4ceO3qUyIfU07t37+BdS3xuZER4OA99VGY5dSrmptC7d+3qJD1xpZq6uroyMzPxiNPOHTsQKwk9eZKHPiqb5eCAGQBgtLW2tBApkWLq6Oi4f+8eHnHav28fYiWBhw\/zbt68ibhiqZMTZgAscXKqq6sjUiLF1NraGh0VhUecjh45gliJn68v1UHYb4OFxc3Tp00rJ21RpJqampoO+vvjEafTYWGIlWzz9uadPXMGcYX31q2YAWCor49OYSXEdaqtrfX08MAjTpHINuOwDN6RoCDEFWBCYQaAmorKs2fPiJRIMRUVFTnOm4dHnK5euYJYyUoXF4p6gBPHj2MGgLKi4k1kBh8hrlNWVtZULIlAwLeRPa8WL1rEQ8+UDA8PxwwAORkZQB2REikm2OA0Ro7EI04pKSnoICcPfVR2JT4eMwCGDBoEmPz27RsRFKkkeLNnTp\/GcwoGjDanp1lZ8RYtXIi44u6dO5gBADzf0ZH0x5VWamhowBlZef36NWIxkydO5NnZ2iKuSH\/8GD8AJk2Y8PjRIyIrUkmlJSWzZ83CJkvorhCG+vo8c1NTxBU5OTn4ATByxIgLERFEVqSS0tPTjcePx+ZPohcDF\/DGGRoirqipqcEPAEV5+c2bNhFZkUo6e+YMbHB4BMl08mTESqqqqv7pDEeJEmVFRcwAGDp4sLmZGUmJk0oPeM3q1Rgm5PHZeelSxGIyMjJ+dYcuKSlBXIenfUVvK0hdnRyHSR+VlZVNNDHBJkXoM66Yy5d\/AeDBgweI67CdWvdk2WHDjgQFkWHx0kRdXV2PHj3CMBagmy9euIBYD7\/nFY+ycj44OBg\/AIAd58378uULkRupoZaWFsxtph6mpSHWs9LFhdaQPIkcBQBra2rmZGcTuZEm+8fc1BSnCKGH5E21sPgFAPRRwIcPHyQCAPDOd\/n4ELmRDgJr9vbt28OVlHCO20IvSUVZ+RcARo8ahbius7MTm9veKyfCdMoUYgVJB339+nWfnx+GwXjdbGJsjFhPXW3tv4OygWF9iKvx9DD6ncFhupGYSKRHCig3J8fyp8mBjdE5Pln\/X5TMo5MzhLk\/3H8qJBcvJrEgrhMYEX6+vpgPlNDl8N1Znjw6PUQxN0nv7Qrn5BAZ4jSVl5eDx4nT\/gGOjY1FLKl7VP0vAOzZvRtx9W28k8J6dQravWsXGZ3NXfr27Rtst\/Kyspglp6qqCrGqtatX\/wcAaIMJPIShgwdLCgN6urpZyOZFhNhMRUVF+LtLoQek9nRrfwFAU0MD\/QELXDVsfSqBFc7OLaRZEAepra0NjA2cp798dlu7lk4I6F8AAL8rKEB8ZrePj6QAwK+UT01J6erqIiLFLcrPyzPQ08MvMNFRUYhV3bp1qw8AoEfFJN+\/L0EAAM+ZPZtMT+Lc9r950yaJSAvYXYiF7di+vQ8ALHd2Zq0bAKykoHAkMJAoAa4QvKmMjIzRo0bhFxVKe75nRgav53AK9MemWVlJVgkY6utfu3aNyBYnqLCw0MbGRiJy4rpqFf2tnNfzk+hW6X6+vpIFAHjDNjNmgAdDxIvl1NjYuMvHR0FeXiJygq6nvXf3bs+LefQbKaakpEgWAPwMp4CAgIaGBiJkrCXYYqOjo\/FHfv6dDo\/0FXfv2tUvAJYsXoz2abC1c0Gw6vDhJ0NCOjo6iKixkDra2+Pj4vR0dSUlHpSWfK+hR7xebQnRXqaNtbXEATBk0KAJJiZX4uNJjhDbCN7Ig+RkMFMlGC\/xcHdHb+K91sbr9Xn0mF5sXa0pq+YnGBvn5uYSDLBK+isqKuxtbWWHDZOgbKB7If7111+9ru8NgJDgYMTnJdImqD+ePHFiTnY2wQBLpD8\/Lw\/\/NIlerDFyJFoe9vn5UQBgwfz56FudgLGqn1IP2NvZgc4lhwOSpc7OzkePHi1xcsKf8daLvbduRS91yqRJFACgdAPAAWWPEhg2ZAjc0rNnzwgGJCj9r16+tLO1lZORkbg8oMtaQEf9\/hHe73\/6+++\/Ed9SXV0tkQpJdM1AXFwcSZnGT62trcn377PEKNDR1kavts+DLJ6gs4WBFi5YwCoADBk0SE1V9XRYGImN4iTYcSIvXgQNjLnSpT\/23bsXvWBACC0AgCWHLhFOvH6dVQDo7iKx3svr\/fv3xC0WN4HBmZeXt83bm99YgSWcm5uLWPPTp0\/7\/BSvz79evnQJddjR0YFnzr0QRfT2traglBvq64mYiolgc4QnPH\/ePJw9TujkiaGXvWXzZgEAYG9nh\/66zRs3shAAv84CVVU9PTzKy8qIKmA81llYWAiWtERyPNF8+NAhtKfe35bN68+qRg\/rzcI16l5or2CsgcHZM2dKS0tJl2lGbB4Q\/bBTpyaamLAtBMLnjx8\/ItaPqGbh9fcPgYcPox+KsZERmzEArD5ixOJFi2JjYr7U1BAYCEdg7lZUVFyJj3davBjbZDtBeaqFBfouVru6CgwASqPq2NGjLAcAXxWAo7Z506aHaWlgvBKjSCD6\/Pnz3bt3vTw9tTQ1WRLq6ZPj4uIQd9HW1oY4oeMhvvf58+eI762pqRE05RUeourw4ROMjW2srefNmbNg\/nz4n8mTJmmNHg2KVayPmO8fJyYmVlZWkmgpmlpaWoo+fIiLjQVXEP94FCFOgdAzRa\/9+Sfi4ygAoEcIA+3csUOgwUe7fHxevXwJKrW1tRXMStiP4VlXVVXl5+dfv34d\/tXWxgYQIj4kKCooWE2dut3bG4zCT58+wd5AjpC7rfyGhoZ3795dvXJlg5eXuampmooK+zU8MHh66FtbtHChkAAAxxn91SDK9PN2pllZgdyj30FlRcXpsDALc3OxZhQCwEapqy9csACeXU5OTlNj40D2EGD7LCsre\/rkCXh9jvPmsTDCg56nCLsY4u5qe3RAERgAwIlUvWk3bdhAEwA2M2ZQ2B7fvwMGQBZhKwL9azx+PIb6GzkZmRnTp4cEB\/\/9998fP34EiIJASLerAHcHt1lXV5eXl3f50qUd27ZNNTeXeB6bOKKfP2gk8FMAwHr6dPQPFBcX0xRTsCb\/+usvxFeVlpb67t27ysUlIyMDYFBYWOjp4YEnuRzwOUJVFSDn4e5+OTr67Zs31dXVICXShATYXOpqawsKCm7fvh0UGLh0yRJDfX0wOCXb7ENEv66+rg5xy\/AGKU9seZQ\/k\/74MfrJ0s8CNxo\/\/uWLF\/1JFcCDH2gDQUxLTeVrZ9ii4I+YQxCgFkyMjZ0WLwYnJzIy8tHDh6UlJaBMv379CkqM\/aiA7aOpqamqsvLDhw+ZmZkJCQmHAgJgZwElPNbAQLIFKwyyz86d6OdwKjSU8kuoATB39mz0z8BWTXMXgcumT5t27969Pm2hysrKgICAiSYm9nZ2Dx8+7I5hXY2Pl1TGFcjKqJEjxxoa\/mFpuXzZMrAWToaExMbE3Lt799mzZ+AyopOmMJvyOdnZSbduRUVGBp84sWvnTteVKx3s7EyMjHS1tWGnZ+cBligtQsAFRT8QbU1NBgAADNs2+umvWL5coKr2o0eO1PbV3QTUNNzV58+fewZn+NVGppMns0RZwzKUFBQ0NTRcV6368P49e06sQk+eBFmXmg0eze7r1qEfCNgOdL6HFgCcFi1C\/9jbt28FLWSxsbb+68EDRPgF\/un5s2eRFy+WlJQABl6\/fj1v7lyWYADU0ZxZs15Q7QuYCfza0NBQCfYjwfn8we5AO\/pG48YxBgD4PRBxUaKtfe6j4ISBlVZeXt6nVQ1u6JzZs8E3ne\/omJubCzoBHAOwoFiSaPT40SO2HajBY6ypqfF0d+doSIc+r3NzQz+KJNoTLXg0r1vp4oL+yXcFBUJYmWBLeG\/dChjo8xzewsyMb+1t+nkkBwKXnJws8R1uuJIS4Ja1rnBBQUGv1jdSxvD8KUcnTqU9j4xHf8NGKx0g4cYgwzebGBvDl\/cSKf5gcf0xY0DiFy1Y0P1H8B9GSK4aAdDo5eGBPnyRuB7IzcnR0dKSVgCAq4N+AumPH9P\/Nh6DbkdTU5PW6NHCYWDZ0qXZr171wgA48g8fPgw7daqnF15WVrZq5UpJOQPGRkYpyJppNlB7e7tAWSocYnj+lMf2jvPmiQUAsPkVFxejf\/vPq1eF3lldV63q0xb6fYd78OCBRMYuAOr8\/PwaGxvZf+yVk52tMny49AHgyZMnzMZjeAJdvXnTJspHbz19upAYGDbMeelSRL4Q+ACgZGADgGvOnT2LXwmMHjXqPWvinpRKYMf27dw95e2TQTwob9zB3l6MAJAdNgxdesP3hoUORcvLygafONGnjmtvazsTFvaHldWFiIj6+vovNTVWU6fiPB0DF3+1qyuHskcfP348Sl1daqRfTkamrLQUfctCjDPlCfqBWQ4OlI++VwdqgRjeWZ8pQxUVFfxR4\/Jycgf27wf3IPP5c5xdiEeOGJGRns6h5B8w1QSNTbOZDwUEUCo9XR0dsQMA+Nqff1JWVAjnDfN5pr3973qmoaGhux+RhZnZ69evuzo7wT\/G1pljpoMDOvWKhdlvt27dYnMlF30GyaZsfNY9+1rsAADhphxaej0hQei7VVJQ2OXj0ysiBHZRfFycupoaXDBl8uQXPycH19TU+OzcicHSBftnn58f55JDKysruZXf3x\/fvHkTfadgHQnXm5En3IIoE\/GAwFgS+obVVFWfPn3a6wvb2trArt20cWNMTEz3ftDU2LjOzU3cjSmVFRVfsizxgQ7BE2NbGz8heKmTE+WdwjXCfTlP6B0RPVcYqLy8XOiyOtjUVzg7\/97fCvZg8IB7aUOwl9zWrhXr+b\/+mDHocjbWHor5+fqyoW2tKE++qakJfZsP09KE\/n6e0J+krJUBSk5OFr6piZpa8v37lC8YTCP4b1VV1RInJ\/Fl\/FLmhLOWwG7krhUkM3RoTk4OZRqsob6+BAAADKYI5QsQLj+Cn3M2wdi4vv8mh9++fYu8eHGli8s+X9\/8vDzYoU+Fho7R1RWH2wf7KEcBUFBQMHniRI4C4PixY5Q3eOL4cVF+gidiZJBSPYGYWk6dKnToN6H\/wcDV1dX8rC8wfuxsbMAka25uvnfv3qyZM1VVVJiCAXwPOOXRUVEcBUBdba2DnR0XpR98SMqoA2h+EZMjeSKucsvmzZTvQBRnYPmyZf09hZqaGvOf6aJ8n2H\/vn38v3\/48OHA\/v3ampoiWkR80TceP36bt\/enT584CgDYFFatXMk56Ye9lTLlU8RACzMAACl5\/fq1+JwBZSWld\/2MfQXr\/0hQUHePYse5c3v6BhXl5WB9WZiZqSgr00cC3I7ssGHKioomRkbr3NxiL19mT9Gj0IEgoa1QCXLqz6JwNNEp+RU7AIAnmJjQSQ8WOll6544d\/SUggBIAExCcPNgwAAy\/W1+lpaX3791zXrp0nKEhXAPq8vdDAxB6MKLAagKlYTV16tYtW64nJBQVFVGedXCCwEcMCgzklvTv8vGhvK+8vDxZJqJbPEZWjB7OKqIzAEYIiCMiElRTXQ1mT88Mon9agPzse1NcXMzfwhsbG9+8eXP79u2LFy4AZg7s2wd+7UF\/f3Czws+fv3njRkZ6OvxK95fAasG9AfuB6wCAOzp39iyHpN9syhR0q0O+Whs\/diwjP8djat0Ib1VEZ0Bm6FB\/f3+BTmHfvn076WfoQ1Feft6cOWDB\/\/5xAAnsjp2\/PWuQmPeFhYcPHVq2dKnb2rX3++lhwaGEiJjLl7ki\/aDM0b0e+OTp4cHULzIGABA12IYpl56RkSGE5tLU0KDMQu3pAFyJj++OAsH\/bFy\/HoylntfA7p6eng5b459Xr5b+N8cwPz8fMNNtKcFO856qFI7lZ2Hx8fFcqXWkLD0HunnzJoM\/ymPwu8AZoGM3305KEjRGCddvWL++urqa5lvPe\/t2oolJtxDPnT27ZxgHDJtlS5bwc7b5pw15PZ570q1b3Uen8K9ggH3gSA1AfwBIECEvC+eZF2yO1EZEWRmzo5l4zN7GiuXL6bwVIazSkerqEeHh3+hZI2C0pKWmggEza+ZM2M5v3bzZncgAAgGWmFKPrt8g7uADdH+28N07+KD+mDF6urrW06dHR0ezuQKYDrFzqGEvvp6QQMecY7zen8f4nVyKjqbzVnz37hVUCZibmf2eIYeg9ra2ivLyz1VVvf4ObvHC+fNhIwElAJbb5IkTe9b7A0I+f\/58584d8JjBb5aCQFBiYiLLpf\/okSN0boSy0y0rACAvK5ufl0fnftb0P7imPwwY6OmBpyF6WnJ7e\/vLly9BMzx8+JDrkX5KE0joQm08DB4tnRvJyswUR947Txy3NM7QkI4z0NnZOVPAkzzAwCoXl5zsbDLYQqCQAGul33HuXDqvEqxWMaX08cR0YzSdAfBHzU1NBc3EXr5sWX5+PhFuugC4coWd0g+vno5\/1djYKL6JjDzx3V5QYCCdN\/TlyxfQGILqARMjo2fPnpFpX3QAcJWVAABrlk62D5Cdra34lsET601GhIfTucPi4mJNDQ1BMaA\/Zsy1a9e4WKdCAGBibFxZWUln\/eLO5BMvAMBroRyy1I0BQfUAsIqyMthaubm5lBXTAxoALHOCwfJBlHmIEipkHQD4BxzoyUjdVFtbK6g\/0A2D7d7eb968ARiQScAsjwI52NvTzLDCk8HBw\/Ab8rKy\/CYOdHxiQTt7\/Rsh1dff7+eXl5fX0tJCYMBOACxcsICm25aSkoJnpA0Pz52rqajk0TscgAe0bMkS4VuqKCrOd3QMCgrKzMwElQJgEC5gCnLT1tYGmrqsrIzTUdd\/AICcFI2N3daupfkYQZkrKSjgWRUP2\/1rjBxJM6EN3tnWLVtETKsyNjJasnixn69vdFRUWlpaTk5O8adP\/EF3oGdaehD8pampCWS9qqqqoKAAkPMgOTk2JiYoMHC9l5e9nZ2FuTl3syFYAgB4oTQXLL6Qv4QBwG9xUfVbYkJ\/xFQZBzji8Lt\/WFqC\/oVNaMf27fv37TsSFBR84gTw8WPH\/A8cgD96eXqCPw0GmJmpqa62tkyP9qawG3H3tJgNAKCZ6QAE25CJsTHOtfEwP4sJJiZ1fY3H65OiIiPZoLsV5eU50RK9PwDExsZK8OnRDIX\/+FnhPtHEBPPyePifCBgnlG1+u+nxo0eCHhEQAPQCgKQKYkaoqYEvS3OdxcXFoKjxL5InkUejNXo0ZWO5bqqpqRHrWSAlK8jJcRsAMTH4H9qMadPojDvhEwgDf0b6QAEAPy6UlZlJ8wF1dXUFHDwoqXEPAICGhgYOm0DYAbBn927Kut5uys7OFrprDocBwBcsmmdk3eaQRCY+yMvJ0cxaIQBQHT6csqFlT3qYloYt4sk6APDPicFCpf+8wE\/Cbw7Jy8p+\/vyZOMGUbGVpWVpSQn9td+\/ckfhcex4bwix0WkB2U2dnp\/+BAzjnPsjJyHAaAHFYALB92zaBknNh42PDCDNWAIB\/UCJQ\/kJKSgo2c4gAAM2G+vpgyQi0qrNnzrBE8NgCgME\/h9HT95z40aF1bm4YVAGoaQKA\/p6Mn6+vQBnpbW1tG9avZ4\/UsQgAgsbO+JSVmTlBzKcn8JrpdGsaaD7ANCurAgHr8sBDYFuvdnYBgH96IlAYge8VnAoNVe7R6YRxAJQI4tuxDQDR0dGMh3rCw8MFTbmF16rKvtndrAMAn3127hS03LGyshKMKDGFqjgNAGYzSpY7O9Ms5uq5Q4GlxE5JYykAhIip8Sn98WOj8eMJAMQBAB1t7Xt37wq6AIkf5HMVAHxVezspSdAnDqrj2NGjivLyTC1j2JAhJcXFAxkAIPpnz5wRIif86dOnEk\/l4jAA+Oy9dWuH4CW\/VVVVu318GDllBAB8ot2al4UUHRUlSu8G+Lhw3TdOhoTgqeqScgDwy6iFG1JUV1t70N9fxFSToYMHF3K5QbRwAJhgYnL1ypWeUxfoU1NT0+JFizghWtwAAD8nOfjECYEOCnq+DzCKhD44AwD0N6aJExQRESHodpOUlCR0XfWtW7e0NTW5IlecAUD3tiRQf9ye1NraejosDMzZgQaA8+fP07xTWxsbgdITe1FZaem8OXO4JVEcAwCf17m50S8r+53AKQTTlgCgZ82nl6dnJu3s9D4pKDBQXlaWc7LESQDwywnCw8OFbtYAH0xLTQUg0Tk+GzJoUAHt8h0WUng\/AID7mungEBsbK+IoNNDJjIeeCQDoWatmZnSGtKLtoj+vXp3v6IiIV9AcBcshAOjp6h4+dEj0w42amhq3tWs5LULcBgDfPtmyebPoFVvV1dXgIfQ3x\/J1bi6HneDw8G5Tx8PdPT09nZHjhQsRERKs5CIA+A+PUlePi4tjRFwK3707sH+\/ro5OTw0gaIoeqwj82j27d6ekpDDSQbWzs\/PqlSsTsLdvIACgFb+7desWU30R8\/Pyzp0967xsmemUKaT5Lv+IPToqSqD4AQGAZEKlYNaTETIMUltb2\/lz54SIIBMASIzHGRrGXL4s3MEZoW5qbm4OCQ7G2auQAIBJHqOrCy5gBzFgBKeGhobAw4elwM0d0AD4lcyopXU6LIzINE0qKiravWsXs\/OoCQAkzxojR+7ds+cdl4+0xG3tXIiIsJkxY+CIxMACQDdPmTQpODiYu2W+zNL3799TU1PXuLpyMZGBAECkE7TZM2fGxMRI96BsBH348OHA\/v0cytwkABBXh0bXVauSk5OFy33nHDU1NUVFRtpYW5NXTwDQ20nYsX17dna29Ak9YDszM\/NIUJCDvb2sjAx51938f9J47hIu9Wl1AAAAAElFTkSuQmCC"
                }
            ]
        }
    ]
    return event


def get_event_with_annotation_object():
    event = deepcopy(_BASE_EVENT)
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
                    "data": "OC44LjguOCBpcyB0aGUgR29vZ2xlIFB1YmxpYyBETlMgSVAgYWRkcmVzc2VzIChJUHY0KS4K"
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
        deepcopy(_TEST_PERSON_OBJECT),
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


def get_event_with_geolocation_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_GEOLOCATION_OBJECT)
    ]
    return event


def get_event_with_image_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        {
            "name": "image",
            "description": "Object describing an image file.",
            "meta-category": "file",
            "uuid": "939b2f03-c487-4f62-a90e-cab7acfee294",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "attachment",
                    "object_relation": "attachment",
                    "value": "STIX.png",
                    "data": "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"
                },
                {
                    "type": "filename",
                    "object_relation": "filename",
                    "value": "STIX.png"
                },
                {
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
                    "object_relation": "description",
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
                    "type": "attachment",
                    "object_relation": "logo",
                    "value": "umbrella_logo",
                    "data": "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"
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
                    "data": "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"
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


def get_event_with_pe_objects():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_PE_OBJECT),
        deepcopy(_TEST_PE_SECTION_OBJECT)
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


def get_event_with_url_object():
    event = deepcopy(_BASE_EVENT)
    event['Event']['Object'] = [
        deepcopy(_TEST_URL_OBJECT)
    ]
    return event


def get_event_with_user_account_object():
    event = deepcopy(_BASE_EVENT)
    user_account = deepcopy(_TEST_USER_ACCOUNT_OBJECT)
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
                "value": "2020-10-25T16:22:00"
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
    for attribute_type, value, uuid in zip(*get_hash_parameters()):
        attribute = {
            'uuid': uuid,
            'type': attribute_type,
            'category': 'Payload delivery',
            'value': value,
            'timestamp': "1603642920",
            'comment': f'{attribute_type.upper()} test attribute',
            'to_ids': to_ids
        }
        yield attribute


def _get_hash_composite_attributes(to_ids):
    indexes = (1, 2, 3, 4, 5, 6, 7, 8)
    for index, attribute_type, value, uuid in zip(indexes, *get_hash_parameters()):
        attribute = {
            'uuid': uuid,
            'type': f'filename|{attribute_type}',
            'category': 'Payload delivery',
            'value': f'filename{index}|{value}',
            'timestamp': "1603642920",
            'comment': f'Filename|{attribute_type} test attribute',
            'to_ids': to_ids
        }
        yield attribute


def get_hash_parameters():
    parameters = (
        ('md5', 'sha1', 'sha224', 'sha512/256', 'sha3-256', 'sha384', 'ssdeep', 'tlsh'),
        (
            'b2a5abfeef9e36964281a31e17b57c97',
            '2920d5e6c579fce772e5506caf03af65579088bd',
            '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9',
            '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
            '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4',
            'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce',
            '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi',
            'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297'
        ),
        (
            '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
            '518b4bcb-a86b-4783-9457-391d548b605b',
            '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
            '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f',
            'f2259650-bc33-4b64-a3a8-a324aa7ea6bb',
            '90bd7dae-b78c-4025-9073-568950c780fb',
            '2007ec09-8137-4a71-a3ce-6ef967bebacf',
            '2d35a390-ccdd-4d6b-a36d-513b05e3682a'
        )
    )
    return parameters
