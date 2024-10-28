#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ._test_stix_import import TestSTIX2Bundles
from base64 import b64encode
from copy import deepcopy
from pathlib import Path
from stix2.parsing import dict_to_stix2

_TESTFILES_PATH = Path(__file__).parent.resolve() / 'attachment_test_files'

_ARTIFACT_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "artifact",
                "mime_type": "application/zip",
                "payload_bin": "UEsDBAoACQAAAKBINlgCq9FEEAAAAAQAAAADABwAb3VpVVQJAAOrIa5lrSGuZXV4CwABBPUBAAAEFAAAAOLQGBmrTcdmURq/qqA1qFFQSwcIAqvRRBAAAAAEAAAAUEsBAh4DCgAJAAAAoEg2WAKr0UQQAAAABAAAAAMAGAAAAAAAAQAAAKSBAAAAAG91aVVUBQADqyGuZXV4CwABBPUBAAAEFAAAAFBLBQYAAAAAAQABAEkAAABdAAAAAAA=",
                "hashes": {
                    "MD5": "bc590af5f7b16b890860248dc0d4c68f",
                    "SHA-1": "003d59659a3e28781aaf03da1ac1cb0e326ed65e",
                    "SHA-256": "2dd39c08867f34010fd9ea1833aa549a02da16950dda4a8ef922113a9eccd963"
                },
                "decryption_key": "infected",
            },
            "1": {
                "type": "artifact",
                "url": "https://files.pythonhosted.org/packages/1a/62/29f55ef42483c30281fab9d3282ac467f215501826f3251678d8ec2da2e1/misp_stix-2.4.183.tar.gz",
                "hashes": {
                    "MD5": "b3982699c1b9a25346cc8498f483b150",
                    "SHA-256": "836f395a4f86e9d1b2f528756c248e76665c02c5d0fc89f9b26136db5ac7f7ae"
                }
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "artifact",
                "mime_type": "application/zip",
                "payload_bin": "UEsDBAoACQAAANVUNlgGfJ2iEAAAAAQAAAADABwAbm9uVVQJAAOhN65lozeuZXV4CwABBPUBAAAEFAAAAE7nhRTz5ElBwvqrXUHYVMlQSwcIBnydohAAAAAEAAAAUEsBAh4DCgAJAAAA1VQ2WAZ8naIQAAAABAAAAAMAGAAAAAAAAQAAAKSBAAAAAG5vblVUBQADoTeuZXV4CwABBPUBAAAEFAAAAFBLBQYAAAAAAQABAEkAAABdAAAAAAA=",
                "hashes": {
                    "MD5": "5bfd0814254d0ff993a83560cb740042",
                    "SHA-1": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                    "SHA-256": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa"
                },
                "decryption_key": "clear",
            }
        }
    }
]
_AS_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "autonomous-system",
                "number": 666,
                "name": "Satan autonomous system"
            },
            "1": {
                "type": "autonomous-system",
                "number": 1234
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "autonomous-system",
                "number": 197869,
                "name": "CIRCL"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--1bf81a4f-0e70-4a34-944b-7e46f67ff7a7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "autonomous-system",
                "number": 50588
            }
        }
    }
]
_ATTACK_PATTERN_OBJECTS = [
    {
        "type": "attack-pattern",
        "id": "attack-pattern--19da6e1c-69a8-4c2f-886d-d620d09d3b5a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "external_references": [
            {
                "source_name": "capec",
                "description": "spear phishing",
                "external_id": "CAPEC-163"
            }
        ],
        "name": "Spear Phishing Attack Pattern used by admin@338",
        "description": "The preferred attack vector used by admin@338 is spear-phishing emails. Using content that is relevant to the target, these emails are designed to entice the target to open an attachment that contains the malicious PIVY server code.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "initial-compromise"
            }
        ]
    },
    {
        "type": "attack-pattern",
        "id": "attack-pattern--ea2c747d-4aa3-4573-8853-37b7159bc180",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Strategic Web Compromise Attack Pattern used by th3bug",
        "description": "Attacks attributed to th3bug use a strategic Web compromise to infect targets. This approach is more indiscriminate, which probably accounts for the more disparate range of targets.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "initial-compromise"
            }
        ]
    }
]
_CAMPAIGN_OBJECTS = [
    {
        "type": "campaign",
        "id": "campaign--752c225d-d6f6-4456-9130-d9580fd4007b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "admin@338",
        "description": "Active since 2008, this campaign mostly targets the financial services industry, though we have also seen activity in the telecom, government, and defense sectors.",
        "first_seen": "2020-10-25T16:22:00.000Z"
    },
    {
        "type": "campaign",
        "id": "campaign--d02a1560-ff69-49f4-ac34-919b8aa4b91e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "th3bug",
        "description": "This ongoing campaign targets a number of industries but appears to prefer targets in higher education and the healthcare sectors.",
        "first_seen": "2020-10-25T16:22:00.000Z"
    }
]
_COURSE_OF_ACTION_OBJECTS = [
    {
        "type": "course-of-action",
        "id": "course-of-action--70b3d5f6-374b-4488-8688-729b6eedac5b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Analyze with FireEye Calamine Toolset",
        "description": "Calamine is a set of free tools to help organizations detect and examine Poison Ivy infections on their systems. The package includes these components: PIVY callback-decoding tool (ChopShop Module) and PIVY memory-decoding tool (PIVY PyCommand Script).",
        "external_references": [
            {
                "source_name": "Calamine ChopShop Module",
                "description": "The FireEye Poison Ivy decoder checks the beginning of each TCP session for possible PIVY challengeresponse sequences. If found, the module will try to validate the response using one or more passwords supplied as arguments.",
                "url": "https://github.com/fireeye/chopshop"
            },
            {
                "source_name": "Calamine PyCommand Script",
                "description": "Helps locate the PIVY password.",
                "url": "https://github.com/fireeye/pycommands"
            }
        ]
    },
    {
        "type": "course-of-action",
        "id": "course-of-action--e84ac8d4-dd81-4b04-81b6-d72137c21c84",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Exploitation for Client Execution Mitigation",
        "description": "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist",
        "external_references": [
            {
                "source_name": "MITRE",
                "url": "https://attack.mitre.org/mitigations/T1203"
            },
            {
                "source_name": "MITRE ATT&CK",
                "external_id": "T1203"
            }
        ]
    }
]
_DIRECTORY_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/misp-stix",
                "path_enc": "ISO-8859-1",
                "created": "2021-07-21T11:44:56Z",
                "modified": "2023-12-12T11:24:30Z",
                "accessed": "2023-12-12T11:24:30Z"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--5ac47782-e1b8-40b6-96b4-02510a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/",
                "path_enc": "ISO-8859-6-I",
                "created": "2014-07-25T10:47:08Z",
                "modified": "2023-12-12T11:34:05Z",
                "accessed": "2023-12-12T11:34:05Z",
                "contains_refs": [
                    "1"
                ]
            },
            "1": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/misp-stix",
                "path_enc": "ISO-8859-1",
                "created": "2021-07-21T11:44:56Z",
                "modified": "2023-12-12T11:24:30Z",
                "accessed": "2023-12-12T11:24:30Z"
            }
        }
    }
]
_DOMAIN_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "domain-name",
                "value": "circl.lu"
            },
            "1": {
                "type": "domain-name",
                "value": "lhc.lu"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "domain-name",
                "value": "misp-project.org"
            }
        }
    }
]
_DOMAIN_IP_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "domain-name",
                "value": "example.com",
                "resolves_to_refs": [
                    "1",
                    "2"
                ]
            },
            "1": {
                "type": "ipv4-addr",
                "value": "198.51.100.3"
            },
            "2": {
                "type": "ipv6-addr",
                "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            }
        }
    }
]
_EMAIL_ADDRESS_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-addr",
                "value": "john.doe@gmail.com",
                "display_name": "John Doe"
            },
            "1": {
                "type": "email-addr",
                "value": "john@doe.org"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-addr",
                "value": "donald.duck@disney.com",
                "display_name": "Donald Duck"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--1bf81a4f-0e70-4a34-944b-7e46f67ff7a7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-addr",
                "value": "donald.duck@gmail.com"
            }
        }
    }
]
_EMAIL_MESSAGE_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-message",
                "is_multipart": True,
                "received_lines": [
                    "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)"
                ],
                "content_type": "multipart/mixed",
                "date": "2016-06-19T14:20:40.000Z",
                "from_ref": "1",
                "to_refs": ["2"],
                "cc_refs": ["3"],
                "subject": "Check out this picture of a cat!",
                "additional_header_fields": {
                    "Content-Disposition": "inline",
                    "X-Mailer": "Mutt/1.5.23",
                    "X-Originating-IP": "198.51.100.3"
                },
                "body_multipart": [
                    {
                        "content_type": "text/plain; charset=utf-8",
                        "content_disposition": "inline",
                        "body": "Cats are funny!"
                    },
                    {
                        "content_type": "image/png",
                        "content_disposition": "attachment; filename=\"tabby.png\"",
                        "body_raw_ref": "4"
                    },
                    {
                        "content_type": "application/zip",
                        "content_disposition": "attachment; filename=\"tabby_pics.zip\"",
                        "body_raw_ref": "5"
                    }
                ]
            },
            "1": {
                "type": "email-addr",
                "value": "jdoe@example.com",
                "display_name": "John Doe"
            },
            "2": {
                "type": "email-addr",
                "value": "bob@example.com",
                "display_name": "Bob Smith"
            },
            "3": {
                "type": "email-addr",
                "value": "mary@example.com",
                "display_name": "Mary Smith"
            },
            "4": {
                "type": "artifact",
                "mime_type": "image/jpeg",
                "payload_bin": "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",
                "hashes": {
                    "SHA-256": "effb46bba03f6c8aea5c653f9cf984f170dcdd3bbbe2ff6843c3e5da0e698766"
                }
            },
            "5": {
                "type": "file",
                "name": "tabby_pics.zip",
                "magic_number_hex": "504B0304",
                "hashes": {
                    "SHA-256": "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db"
                }
            }
        }
    }
]
_FILE_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "file",
                "hashes": {
                    "MD5": "8764605c6f388c89096b534d33565802",
                    "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                    "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                },
                "size": 35,
                "name": "oui",
                "name_enc": "UTF-8",
                "parent_directory_ref": "1",
                "content_ref": "2"
            },
            "1": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/tmp"
            },
            "2": {
                "type": "artifact",
                "mime_type": "application/zip",
                "hashes": {
                    "MD5": "8764605c6f388c89096b534d33565802"
                },
                "encryption_algorithm": "mime-type-indicated",
                "decryption_key": "infected"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--1a165e68-ea72-44e6-b821-3b88f2cc46d8",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "file",
                "name": "oui.zip",
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
                },
                "mime_type": "application/zip",
                "extensions": {
                    "archive-ext": {
                        "comment": "Zip file containing `oui` in the tmp directory",
                        "contains_refs": [
                            "1",
                            "2"
                        ]
                    }
                }
            },
            "1": {
                "type": "file",
                "hashes": {
                    "MD5": "8764605c6f388c89096b534d33565802",
                    "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                    "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                },
                "size": 35,
                "name": "oui",
                "name_enc": "UTF-8",
                "parent_directory_ref": "2",
                "content_ref": "3"
            },
            "2": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/tmp"
            },
            "3": {
                "type": "artifact",
                "mime_type": "application/zip",
                "hashes": {
                    "MD5": "8764605c6f388c89096b534d33565802"
                },
                "encryption_algorithm": "mime-type-indicated",
                "decryption_key": "infected"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "file",
                "hashes": {
                    "MD5": "b1de37bf229890ac181bdef1ad8ee0c2",
                    "SHA-1": "ffdb3cc7ab5b01d276d23ac930eb21ffe3202d11",
                    "SHA-256": "99b80c5ac352081a64129772ed5e1543d94cad708ba2adc46dc4ab7a0bd563f1",
                    "SHA-512": "e41df636a36ac0cce38e7db5c2ce4d04a1a7f9bc274bdf808912d14067dc1ef478268035521d0d4b7bcf96facce7f515560b38a7ebe47995d861b9c482e07e25",
                    "SSDEEP": "98304:z2eyMq4PuR5d7wgdo0OFfnFJkEUCGdaQLhpYYEfRTl6sysy:ryxzbdo0ifnoEOdz9pY7j5"
                },
                "size": 3712512,
                "name": "SMSvcService.exe",
                "extensions": {
                    "windows-pebinary-ext": {
                        "pe_type": "exe",
                        "number_of_sections": 4,
                        "time_date_stamp": "1970-01-01T00:00:00Z",
                        "size_of_optional_header": 512,
                        "sections": [
                            {
                                "name": "header",
                                "size": 512,
                                "entropy": 2.499747,
                                "hashes": {
                                    "MD5": "7f8e8722da728b6e834260b5a314cbac"
                                }
                            },
                            {
                                "name": "UPX0",
                                "size": 0,
                                "entropy": 0.0,
                                "hashes": {
                                    "MD5": "d41d8cd98f00b204e9800998ecf8427e"
                                }
                            },
                            {
                                "name": "UPX1",
                                "size": 3711488,
                                "entropy": 7.890727,
                                "hashes": {
                                    "MD5": "f9943591918adeeeee7da80e4d985a49"
                                }
                            },
                            {
                                "name": "UPX2",
                                "size": 512,
                                "entropy": 1.371914,
                                "hashes": {
                                    "MD5": "5c0061445ac2f8e6cadf694e54146914"
                                }
                            }
                        ]
                    }
                }
            }
        }
    }
]
_INTRUSION_SET_OBJECTS = [
    {
        "type": "intrusion-set",
        "id": "intrusion-set--da1065ce-972c-4605-8755-9cd1074e3b5a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "APT1",
        "description": "APT1 is a single organization of operators that has conducted a cyber espionage campaign against a broad range of victims since at least 2006.",
        "first_seen": "2020-10-25T16:22:00.000Z",
        "resource_level": "government",
        "primary_motivation": "organizational-gain",
        "aliases": [
            "Comment Crew",
            "Comment Group",
            "Shady Rat"
        ]
    },
    {
        "type": "intrusion-set",
        "id": "intrusion-set--10df003c-7831-41e7-bdb9-971cdd1218df",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Lazarus Group - G0032",
        "first_seen": "2020-10-25T16:22:00.000Z",
        "resource_level": "government",
        "primary_motivation": "organizational-gain",
        "aliases": [
            "Lazarus Group",
            "HIDDEN COBRA",
            "Guardians of Peace",
            "ZINC",
            "NICKEL ACADEMY"
        ]
    }
]
_IP_ADDRESS_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "8.8.8.8"
            },
            "1": {
                "type": "ipv6-addr",
                "value": "2001:4860:4860::8888"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "185.194.93.14"
            }
        }
    }
]
_MAC_ADDRESS_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "mac-addr",
                "value": "d2:fb:49:24:37:18"
            },
            "1": {
                "type": "mac-addr",
                "value": "62:3e:5f:53:ac:68"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "mac-addr",
                "value": "ae:49:db:d4:d9:cf"
            }
        }
    }
]
_MALWARE_OBJECTS = [
    {
        "type": "malware",
        "id": "malware--2485b844-4efe-4343-84c8-eb33312dd56f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MANITSME",
        "labels": [
            "backdoor",
            "dropper",
            "remote-access-trojan"
        ],
        "description": "This malware will beacon out at random intervals to the remote attacker. The attacker can run programs, execute arbitrary commands, and easily upload and download files."
    },
    {
        "type": "malware",
        "id": "malware--c0217091-9d3d-42a1-8952-ccc12d4ad8d0",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "WEBC2-UGX",
        "labels": [
            "backdoor",
            "remote-access-trojan"
        ],
        "description": "A WEBC2 backdoor is designed to retrieve a Web page from a C2 server. It expects the page to contain special HTML tags; the backdoor will attempt to interpret the data between the tags as commands."
    }
]
_MUTEX_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "mutex",
                "name": "shared_resource_lock"
            },
            "1": {
                "type": "mutex",
                "name": "thread_synchronization_lock"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "mutex",
                "name": "sensitive_resource_lock"
            }
        }
    }
]
_NETWORK_TRAFFIC_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "198.51.100.2"
            },
            "1": {
                "type": "ipv4-addr",
                "value": "203.0.113.1"
            },
            "2": {
                "type": "ipv4-addr",
                "value": "203.0.113.2"
            },
            "3": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "1",
                "src_port": 2487,
                "dst_port": 1723,
                "protocols": [
                    "ipv4",
                    "pptp"
                ],
                "src_byte_count": 35779,
                "dst_byte_count": 935750,
                "encapsulates_refs": [
                    "4"
                ]
            },
            "4": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "2",
                "src_port": 24678,
                "dst_port": 80,
                "protocols": [
                    "ipv4",
                    "tcp",
                    "http"
                ],
                "src_packets": 14356,
                "dst_packets": 14356,
                "encapsulated_by_ref": "3"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "203.0.113.1"
            },
            "1": {
                "type": "ipv4-addr",
                "value": "198.51.100.34"
            },
            "2": {
                "type": "ipv4-addr",
                "value": "198.51.100.54"
            },
            "3": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "1",
                "src_port": 2487,
                "dst_port": 53,
                "protocols": [
                    "ipv4",
                    "udp",
                    "dns"
                ],
                "src_byte_count": 35779,
                "dst_byte_count": 935750,
                "encapsulates_refs": [
                    "4"
                ]
            },
            "4": {
                "type": "network-traffic",
                "src_ref": "1",
                "dst_ref": "2",
                "src_port": 24678,
                "dst_port": 443,
                "protocols": [
                    "ipv4",
                    "tcp",
                    "ssl",
                    "http"
                ],
                "src_packets": 14356,
                "dst_packets": 14356,
                "encapsulated_by_ref": "3"
            }
        }
    }
]
_PROCESS_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "process",
                "pid": 2510,
                "name": "TestProcess",
                "binary_ref": "4",
                "parent_ref": "1",
                "child_refs": [
                    "3"
                ],
                "is_hidden": True
            },
            "1": {
                "type": "process",
                "pid": 2107,
                "name": "Friends_From_H",
                "cwd": "/home/viktor",
                "created": "2017-05-01T08:00:00Z",
                "command_line": "grep -nrG iglocska ${HOME}/friends.txt",
                "environment_variables": {
                    "HOME": "/home/viktor",
                    "USER": "viktor"
                },
                "binary_ref": "2"
            },
            "2": {
                "type": "file",
                "name": "parent_process.exe",
                "size": 12367,
                "name_enc": "UTF-8",
                "mime_type": "application/exe"
            },
            "3": {
                "type": "process",
                "pid": 1401,
                "name": "ChildProcess"
            },
            "4": {
                "type": "file",
                "name": "test_process.exe",
                "size": 82639,
                "name_enc": "UTF-8",
                "mime_type": "application/exe"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "process",
                "pid": 666,
                "name": "SatanProcess",
                "command_line": "rm -rf *"
            }
        }
    }
]
_REGISTRY_KEY_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "windows-registry-key",
                "key": "hkey_local_machine\\system\\bar\\baz",
                "modified": "2020-10-25T16:22:00Z",
                "values": [
                    {
                        "name": "RegistryName",
                        "data": "%DATA%\\baz",
                        "data_type": "REG_SZ"
                    }
                ]
            },
            "1": {
                "type": "windows-registry-key",
                "key": "hkey_local_machine\\system\\bar\\foo",
                "modified": "2020-10-25T16:22:00Z",
                "number_of_subkeys": 2,
                "creator_user_ref": "2",
                "values": [
                    {
                        "name": "Foo",
                        "data": "qwerty",
                        "data_type": "REG_SZ"
                    },
                    {
                        "name": "Bar",
                        "data": "42",
                        "data_type": "REG_DWORD"
                    }
                ]
            },
            "2": {
                "type": "user-account",
                "user_id": "john.doe",
                "account_login": "JohnDoe",
                "account_type": "windows-local",
                "is_privileged": True
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "windows-registry-key",
                "key": "hkey_local_machine\\system\\foo\\fortytwo",
                "modified": "2020-10-25T16:22:00Z",
                "values": [
                    {
                        "name": "FortyTwoFoo",
                        "data": "%DATA%\\42",
                        "data_type": "REG_QWORD"
                    }
                ]
            }
        }
    }
]
_SOFTWARE_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "software",
                "name": "MISP",
                "languages": [
                    "PHP"
                ],
                "vendor": "MISP Project",
                "version": "2.4.183"
            },
            "1": {
                "type": "software",
                "name": "misp-stix",
                "languages": [
                    "Python"
                ],
                "vendor": "CIRCL",
                "version": "2.4.183"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "software",
                "name": "Acrobat X Pro",
                "cpe": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
                "swid": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>",
                "languages": [
                    "C#",
                    "Javascript",
                    "Postscript"
                ],
                "vendor": "Adobe Inc.",
                "version": "10.0"
            }
        }
    }
]
_THREAT_ACTOR_OBJECTS = [
    {
        "type": "threat-actor",
        "id": "threat-actor--6d179234-61fc-40c4-ae86-3d53308d8e65",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Ugly Gorilla",
        "labels": [
            "nation-state",
            "spy"
        ],
        "roles": [
            "malware-author",
            "agent",
            "infrastructure-operator"
        ],
        "resource_level": "government",
        "aliases": [
            "Greenfield",
            "JackWang",
            "Wang Dong"
        ],
        "primary_motivation": "organizational-gain"
    },
    {
        "type": "threat-actor",
        "id": "threat-actor--d84cf283-93be-4ca7-890d-76c63eff3636",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "DOTA",
        "labels": [
            "nation-state",
            "spy"
        ],
        "aliases": [
            "dota",
            "Rodney",
            "Raith"
        ],
        "resource_level": "government",
        "roles": [
            "agent",
            "infrastructure-operator"
        ],
        "primary_motivation": "organizational-gain"
    }
]
_TOOL_OBJECTS = [
    {
        "type": "tool",
        "id": "tool--ce45f721-af14-4fc0-938c-000c16186418",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "cachedump",
        "labels": [
            "credential-exploitation"
        ],
        "description": "This program extracts cached password hashes from a system’s registry.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "escalate-privileges"
            }
        ]
    },
    {
        "type": "tool",
        "id": "tool--e9778c42-bc2f-4eda-9fb4-6a931834f68c",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "fgdump",
        "labels": [
            "credential-exploitation"
        ],
        "description": "Windows password hash dumper",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "escalate-privileges"
            }
        ],
        "external_references": [
            {
                "source_name": "fgdump",
                "url": "http://www.foofus.net/fizzgig/fgdump/"
            }
        ]
    }
]
_URL_ATTRIBUTES = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "url",
                "value": "https://circl.lu/team/"
            },
            "1": {
                "type": "url",
                "value": "https://cybersecurity.lu/entity/324"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "url",
                "value": "https://misp-project.org/blog/"
            }
        }
    }
]
_USER_ACCOUNT_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1001",
                "account_login": "jdoe",
                "account_type": "unix",
                "display_name": "John Doe",
                "is_service_account": False,
                "is_privileged": False,
                "can_escalate_privs": True,
                "account_created": "2016-01-20T12:31:12Z",
                "password_last_changed": "2016-01-20T14:27:43Z",
                "account_first_login": "2016-01-20T14:26:07Z",
                "account_last_login": "2016-07-22T16:08:28Z"
            },
            "1": {
                "type": "user-account",
                "user_id": "thegrugq_ebooks",
                "account_login": "thegrugq_ebooks",
                "account_type": "twitter",
                "display_name": "the grugq"
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1001",
                "account_login": "jdoe",
                "account_type": "unix",
                "display_name": "John Doe",
                "is_service_account": False,
                "is_privileged": False,
                "can_escalate_privs": True,
                "extensions": {
                    "unix-account-ext": {
                        "gid": 1001,
                        "groups": ["wheel"],
                        "home_dir": "/home/jdoe",
                        "shell": "/bin/bash"
                    }
                }
            }
        }
    }
]
_VULNERABILITY_OBJECTS = [
    {
        "type": "vulnerability",
        "id": "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "CVE-2012-0158",
        "description": "Weaponized Microsoft Word document used by admin@338",
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2012-0158"
            }
        ]
    },
    {
        "type": "vulnerability",
        "id": "vulnerability--6a2eab9c-9789-4437-812b-d74323fa3bca",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "CVE-2009-4324",
        "description": "Adobe acrobat PDF's used by admin@338",
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2009-4324"
            }
        ]
    }
]
_X509_OBJECTS = [
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "x509-certificate",
                "is_self_signed": False,
                "hashes": {
                    "MD5": "a39a417abcbe62460665c9da765aefbe",
                    "SHA-1": "bffc1a508d3c02d4a3f86941d3a99f7bf9ec3895",
                    "SHA-256": "caf71b19bf181230a3b203a6c3beaceb4d261409a8dbeef2e1d9eb4a5e0182c6"
                },
                "version": "3",
                "serial_number": "00:bb:ae:27:7a:c3:d9:cf:3f:85:00:86:a3:14:e7:0a:d7",
                "signature_algorithm": "sha256WithRSAEncryption",
                "issuer": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Code Signing CA",
                "validity_not_before": "2017-11-12T00:00:00Z",
                "validity_not_after": "2018-09-12T23:59:59Z",
                "subject": "C=GB/postalCode=EC1V 2NX, ST=London, L=London/street=Kemp House, 160 City Road, O=CYBASICS LTD, CN=CYBASICS LTD",
                "subject_public_key_algorithm": "rsaEncryption",
                "subject_public_key_modulus": "c7:97:8a:4c:a0:6b:9c:91:d0:ed:7e:74:ca:8c:48:41:84:cf:fa:f1:07:ae:51:3f:d1:cb:3c:2e:43:1e:c3:dc:c2:e7:fa:60:cd:c7:25:2c:c4:2e:1c:e0:c2:a2:63:8b:df:f7:1a:55:c8:66:0d:eb:a9:a7:9e:f6:89:6e:ca:63:be:b8:75:18:56:6d:53:c1:8b:b4:f6:b5:04:6d:cc:0f:17:e0:b5:12:70:d6:b5:55:77:76:98:de:84:44:55:6d:5f:8a:a6:1e:a8:62:47:22:96:3d:5a:85:c9:9f:00:f3:3b:c6:ec:cb:68:ff:34:ab:73:d7:02:b6:29:aa:ff:87:1b:39:87:e5:0f:fd:f0:6a:d6:de:81:a3:e6:05:61:5d:84:6c:1f:5e:20:ae:c1:93:56:45:37:b7:c0:d6:6d:ab:27:f6:98:70:cf:a2:9b:c8:4a:04:2d:dc:01:fb:1a:f1:dc:8f:4c:31:7c:c4:71:4a:1c:d7:81:ed:1a:04:cb:4d:aa:3b:37:94:d3:7d:14:c4:4c:0e:8d:eb:75:1c:26:46:35:1c:83:2a:09:cf:41:c9:cb:c6:8c:a6:db:28:90:48:17:92:ff:70:db:5c:4f:d2:27:1a:51:2b:1f:12:f8:f6:ee:8a:88:15:fd:68:13:f0:7a:50:4f:8e:23:d5:4d:51",
                "subject_public_key_exponent": 65537
            },
            "1": {
                "type": "x509-certificate",
                "is_self_signed": False,
                "hashes": {
                    "MD5": "219794f8f6128c731f476d11e7fa5d4f",
                    "SHA-1": "d02be9aa68a05fdf7e99899a9719f275db5e6b2f",
                    "SHA-256": "0adb35fcd170c6da0e45a00c9b36533b21dc2bcf793e6facf0eb30829cbcc5fb"
                },
                "version": "3",
                "serial_number": "00:bc:b4:e7:32:76:0e:ca:64:31:8e:17:6c:fd:4a:ef:30",
                "signature_algorithm": "sha256WithRSAEncryption",
                "issuer": "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Code Signing CA",
                "validity_not_before": "2015-12-08T00:00:00Z",
                "validity_not_after": "2016-12-07T23:59:59Z",
                "subject": "/C=GB/postalCode=RG12 2LS/ST=Berkshire/L=Bracknell/street=15  Shepherds Hill/postOfficeBox=RG12 2LS/O=Network Software Ltd/CN=Network Software Ltd",
                "subject_public_key_algorithm": "sha256WithRSAEncryption",
                "subject_public_key_modulus": "00:ae:29:f8:d7:56:2f:fd:61:40:89:6f:cc:a3:1c:e0:49:0c:21:9f:5e:60:0c:a9:dc:cf:5f:79:83:fd:12:8f:f3:fc:c1:49:a3:e2:9c:a8:e9:d2:88:44:16:bd:39:2e:23:5b:84:e9:54:70:4b:ce:e3:c2:19:fd:a4:8b:45:ca:ad:aa:08:ae:cc:ab:8f:eb:60:74:fa:e0:2b:e5:d1:7b:5d:87:43:26:71:96:d1:ec:5f:23:15:40:37:0e:cc:b1:e1:5a:57:f1:24:58:2c:d6:04:f3:8e:34:9a:ea:bb:88:d5:9b:c3:38:8d:e4:90:7b:e7:ef:89:ea:31:92:97:46:80:f9:f8:b2:78:53:19:b8:66:15:37:af:32:08:58:3f:42:1a:67:f5:9a:40:b7:25:75:dc:3c:5f:b1:7c:12:63:f8:2b:60:93:b5:04:c4:10:9c:2d:1f:aa:9f:af:b1:e9:ee:70:21:fb:7e:aa:b3:1a:8e:e4:4c:18:6e:6a:5d:c4:61:e3:bd:83:d2:af:c6:ce:bc:f8:b8:0f:db:e0:9e:ec:f4:e2:61:99:ee:81:63:d1:71:e4:a7:2b:de:5c:0a:6d:2e:33:94:50:1f:33:e9:bb:1c:eb:e6:d2:18:3d:4f:02:02:dc:30:2e:52:19:4f:9c:0d:15:9d:56:f1:cb:30:59:57",
                "subject_public_key_exponent": 65537
            }
        }
    },
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "x509-certificate",
                "is_self_signed": False,
                "hashes": {
                    "MD5": "09716af84e900e403494c28ad8c5869c",
                    "SHA-1": "1456d8a00d8be963e2224d845b12e5084ea0b707",
                    "SHA-256": "2d23636c25eb5c1b473e0ae66fdb076687b40bd080f161c79663572f171d5598"
                },
                "version": "3",
                "serial_number": "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f",
                "signature_algorithm": "sha256WithRSAEncryption",
                "issuer": "C=US, O=thawte, Inc., CN=thawte SHA256 Code Signing CA",
                "validity_not_before": "2017-07-09T00:00:00Z",
                "validity_not_after": "2018-07-09T23:59:59Z",
                "subject": "C=GB, ST=London, L=London, O=Ziber Ltd, CN=Ziber Ltd",
                "subject_public_key_algorithm": "rsaEncryption",
                "subject_public_key_modulus": "00:e2:12:e4:5c:44:90:fa:0f:75:77:c8:88:51:21:1d:ce:b8:0e:f2:73:d5:68:79:02:50:51:5f:2c:a3:82:d1:48:60:f8:fa:c7:75:72:12:bc:b9:7c:d9:12:a8:1a:18:3a:f9:1d:a9:18:04:59:cd:8a:81:03:f7:0a:3d:22:6e:7d:63:65:d7:4d:c5:65:0e:fc:4f:97:9c:e0:3d:52:a4:d9:0b:d9:04:c3:f3:52:2a:a3:cc:e2:82:2c:2b:b8:54:1b:cc:41:2b:1b:76:d0:2a:fd:65:c4:3f:a2:4b:36:5f:5a:79:28:4b:98:1e:38:6c:b6:33:d2:3d:db:53:9c:0b:3f:2b:ab:87:2e:94:47:72:4f:27:58:8d:b0:b2:38:5f:1d:e0:67:53:6e:38:c7:ac:24:49:c9:b6:81:42:e0:06:95:26:c0:c9:bf:5e:7f:1b:92:f5:58:8e:8a:70:88:a9:e5:82:5c:5c:71:54:e0:74:1b:a9:33:1a:f2:3d:bf:9d:1b:45:1a:0e:02:d8:a3:d8:db:64:a9:f8:28:16:7f:4e:c3:ee:33:a1:be:18:72:e3:bd:79:12:54:ea:b9:77:9b:d0:d0:b0:2d:75:af:4d:47:4e:c1:16:84:a2:88:65:ef:18:ff:33:2a:ab:83:7c:43:14:ad:b8:cd:f0:b9:7c:c1:23",
                "subject_public_key_exponent": 65537
            }
        }
    }
]


class TestExternalSTIX20Bundles(TestSTIX2Bundles):
    __bundle = {
        "type": "bundle",
        "id": "bundle--314e4210-e41a-4952-9f3c-135d7d577112",
        "spec_version": "2.0"
    }
    __identity = {
        "type": "identity",
        "id": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-Project",
        "identity_class": "organization"
    }
    __report = {
        "type": "report",
        "id": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-STIX-Converter test event",
        "published": "2020-10-25T16:22:00Z",
        "labels": ["Threat-Report"]
    }
    __indicator = {
        "type": "indicator",
        "id": "indicator--031778a4-057f-48e6-9db9-c8d72b81ccd5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "HTRAN Hop Point Accessor",
        "description": "Test description.",
        "pattern": "[ipv4-addr:value = '223.166.0.0/15']",
        "labels": [
            "malicious-activity"
        ],
        "valid_from": "2020-10-25T16:22:00.000Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "establish-foothold"
            }
        ]
    }

    @classmethod
    def __assemble_bundle(cls, *stix_objects):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            deepcopy(cls.__identity), deepcopy(cls.__report), *stix_objects
        ]
        bundle['objects'][1]['object_refs'] = [
            stix_object['id'] for stix_object in stix_objects
        ]
        return dict_to_stix2(bundle, allow_custom=True)

    @classmethod
    def __assemble_galaxy_bundle(cls, event_galaxy, attribute_galaxy):
        relationship = {
            "type": "relationship",
            "id": "relationship--7cede760-b866-490e-ad5b-1df34bc14f8d",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "relationship_type": "indicates",
            "source_ref": cls.__indicator['id'],
            "target_ref": attribute_galaxy['id']
        }
        bundle = deepcopy(cls.__bundle)
        report = deepcopy(cls.__report)
        indicator = deepcopy(cls.__indicator)
        report.update(
            cls._populate_references(
                event_galaxy['id'], indicator['id'],
                attribute_galaxy['id'], relationship['id']
            )
        )
        bundle['objects'] = [
            deepcopy(cls.__identity), report, event_galaxy,
            indicator, attribute_galaxy, relationship
        ]
        return dict_to_stix2(bundle, allow_custom=True)

    ############################################################################
    #                              EVENTS SAMPLES                              #
    ############################################################################

    @classmethod
    def get_bundle_with_report_description(cls):
        bundle = deepcopy(cls.__bundle)
        indicator = deepcopy(cls.__indicator)
        report = cls._handle_report_with_description(
            deepcopy(cls.__report), indicator['id']
        )
        bundle['objects'] = [deepcopy(cls.__identity), report, indicator]
        return dict_to_stix2(bundle, allow_custom=True)

    @classmethod
    def get_bundle_without_report(cls):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            deepcopy(cls.__identity), *_IP_ADDRESS_ATTRIBUTES
        ]
        return dict_to_stix2(bundle, allow_custom=True)

    ############################################################################
    #                             GALAXIES SAMPLES                             #
    ############################################################################

    @classmethod
    def get_bundle_with_attack_pattern_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_ATTACK_PATTERN_OBJECTS)

    @classmethod
    def get_bundle_with_campaign_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_CAMPAIGN_OBJECTS)

    @classmethod
    def get_bundle_with_course_of_action_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_COURSE_OF_ACTION_OBJECTS)

    @classmethod
    def get_bundle_with_intrusion_set_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_INTRUSION_SET_OBJECTS)

    @classmethod
    def get_bundle_with_malware_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_MALWARE_OBJECTS)

    @classmethod
    def get_bundle_with_threat_actor_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_THREAT_ACTOR_OBJECTS)

    @classmethod
    def get_bundle_with_tool_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_TOOL_OBJECTS)

    @classmethod
    def get_bundle_with_vulnerability_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_VULNERABILITY_OBJECTS)

    ############################################################################
    #                          OBSERVED DATA SAMPLES.                          #
    ############################################################################

    @classmethod
    def get_bundle_with_artifact_objects(cls):
        return cls.__assemble_bundle(*_ARTIFACT_OBJECTS)

    @classmethod
    def get_bundle_with_as_objects(cls):
        return cls.__assemble_bundle(*_AS_OBJECTS)

    @classmethod
    def get_bundle_with_directory_objects(cls):
        return cls.__assemble_bundle(*_DIRECTORY_OBJECTS)

    @classmethod
    def get_bundle_with_domain_attributes(cls):
        return cls.__assemble_bundle(*_DOMAIN_ATTRIBUTES)

    @classmethod
    def get_bundle_with_domain_ip_objects(cls):
        return cls.__assemble_bundle(*_DOMAIN_IP_OBJECTS)

    @classmethod
    def get_bundle_with_email_address_attributes(cls):
        return cls.__assemble_bundle(*_EMAIL_ADDRESS_ATTRIBUTES)


    @classmethod
    def get_bundle_with_email_message_objects(cls):
        return cls.__assemble_bundle(*_EMAIL_MESSAGE_OBJECTS)

    @classmethod
    def get_bundle_with_file_objects(cls):
        observed_data = deepcopy(_FILE_OBJECTS)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            payload_bin = b64encode(f.read()).decode()
            observed_data[0]['objects']['2']['payload_bin'] = payload_bin
            observed_data[1]['objects']['3']['payload_bin'] = payload_bin
        return cls.__assemble_bundle(*observed_data)

    @classmethod
    def get_bundle_with_ip_address_attributes(cls):
        return cls.__assemble_bundle(*_IP_ADDRESS_ATTRIBUTES)

    @classmethod
    def get_bundle_with_mac_address_attributes(cls):
        return cls.__assemble_bundle(*_MAC_ADDRESS_ATTRIBUTES)

    @classmethod
    def get_bundle_with_mutex_attributes(cls):
        return cls.__assemble_bundle(*_MUTEX_ATTRIBUTES)

    @classmethod
    def get_bundle_with_network_traffic_objects(cls):
        return cls.__assemble_bundle(*_NETWORK_TRAFFIC_OBJECTS)

    @classmethod
    def get_bundle_with_process_objects(cls):
        return cls.__assemble_bundle(*_PROCESS_OBJECTS)

    @classmethod
    def get_bundle_with_registry_key_objects(cls):
        return cls.__assemble_bundle(*_REGISTRY_KEY_OBJECTS)

    @classmethod
    def get_bundle_with_software_objects(cls):
        return cls.__assemble_bundle(*_SOFTWARE_OBJECTS)

    @classmethod
    def get_bundle_with_url_attributes(cls):
        return cls.__assemble_bundle(*_URL_ATTRIBUTES)

    @classmethod
    def get_bundle_with_user_account_objects(cls):
        return cls.__assemble_bundle(*_USER_ACCOUNT_OBJECTS)

    @classmethod
    def get_bundle_with_x509_objects(cls):
        return cls.__assemble_bundle(*_X509_OBJECTS)
