#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from copy import deepcopy
from pathlib import Path
from stix2.parsing import dict_to_stix2

_TESTFILES_PATH = Path(__file__).parent.resolve() / 'attachment_test_files'

_ARTIFACT_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "artifact--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "artifact--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "mime_type": "application/zip",
        "payload_bin": "UEsDBAoACQAAAKBINlgCq9FEEAAAAAQAAAADABwAb3VpVVQJAAOrIa5lrSGuZXV4CwABBPUBAAAEFAAAAOLQGBmrTcdmURq/qqA1qFFQSwcIAqvRRBAAAAAEAAAAUEsBAh4DCgAJAAAAoEg2WAKr0UQQAAAABAAAAAMAGAAAAAAAAQAAAKSBAAAAAG91aVVUBQADqyGuZXV4CwABBPUBAAAEFAAAAFBLBQYAAAAAAQABAEkAAABdAAAAAAA=",
        "hashes": {
            "MD5": "bc590af5f7b16b890860248dc0d4c68f",
            "SHA-1": "003d59659a3e28781aaf03da1ac1cb0e326ed65e",
            "SHA-256": "2dd39c08867f34010fd9ea1833aa549a02da16950dda4a8ef922113a9eccd963"
        },
        "decryption_key": "infected",
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--5e384ae7-672c-4250-9cda-3b4da964451a",
        "url": "https://files.pythonhosted.org/packages/1a/62/29f55ef42483c30281fab9d3282ac467f215501826f3251678d8ec2da2e1/misp_stix-2.4.183.tar.gz",
        "hashes": {
            "MD5": "b3982699c1b9a25346cc8498f483b150",
            "SHA-256": "836f395a4f86e9d1b2f528756c248e76665c02c5d0fc89f9b26136db5ac7f7ae"
        }
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "mime_type": "application/zip",
        "payload_bin": "UEsDBAoACQAAANVUNlgGfJ2iEAAAAAQAAAADABwAbm9uVVQJAAOhN65lozeuZXV4CwABBPUBAAAEFAAAAE7nhRTz5ElBwvqrXUHYVMlQSwcIBnydohAAAAAEAAAAUEsBAh4DCgAJAAAA1VQ2WAZ8naIQAAAABAAAAAMAGAAAAAAAAQAAAKSBAAAAAG5vblVUBQADoTeuZXV4CwABBPUBAAAEFAAAAFBLBQYAAAAAAQABAEkAAABdAAAAAAA=",
        "hashes": {
            "MD5": "5bfd0814254d0ff993a83560cb740042",
            "SHA-1": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
            "SHA-256": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa"
        },
        "decryption_key": "clear",
    }
]
_AS_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "autonomous-system--46f7e73f-36e5-40dd-9b27-735a0a6b44c2",
            "autonomous-system--49713b77-b6ee-4069-a1b4-2a8ad49adf62"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "autonomous-system--81294150-8f7a-453d-a1d8-96c2cfe04efa"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--1bf81a4f-0e70-4a34-944b-7e46f67ff7a7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "autonomous-system--cd890f31-5825-4fea-85ca-0b3ab3872926"
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--46f7e73f-36e5-40dd-9b27-735a0a6b44c2",
        "number": 666,
        "name": "Satan autonomous system"
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--49713b77-b6ee-4069-a1b4-2a8ad49adf62",
        "number": 1234
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--81294150-8f7a-453d-a1d8-96c2cfe04efa",
        "number": 197869,
        "name": "CIRCL"
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--cd890f31-5825-4fea-85ca-0b3ab3872926",
        "number": 50588
    }
]
_ATTACK_PATTERN_OBJECTS = [
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "directory--5e384ae7-672c-4250-9cda-3b4da964451a",
            "directory--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--e812789e-e49d-47e2-b334-8ee0e8a766ce",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "directory--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "directory",
        "spec_version": "2.1",
        "id": "directory--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "path": "/var/www/MISP",
        "path_enc": "UTF-8",
        "ctime": "2011-11-26T10:45:31Z",
        "mtime": "2023-12-12T11:34:05Z",
        "atime": "2023-12-12T11:34:05Z",
        "contains_refs": [
            "directory--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "directory",
        "spec_version": "2.1",
        "id": "directory--5e384ae7-672c-4250-9cda-3b4da964451a",
        "path": "/var/www/MISP/app/files/scripts",
        "path_enc": "ISO-8859-6-I",
        "ctime": "2014-07-25T10:47:08Z",
        "mtime": "2023-12-12T11:34:05Z",
        "atime": "2023-12-12T11:34:05Z",
        "contains_refs": [
            "directory--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "directory",
        "spec_version": "2.1",
        "id": "directory--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "path": "/var/www/MISP/app/files/scripts/misp-stix",
        "path_enc": "ISO-8859-1",
        "ctime": "2021-07-21T11:44:56Z",
        "mtime": "2023-12-12T11:24:30Z",
        "atime": "2023-12-12T11:24:30Z"
    }
]
_DOMAIN_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "domain-name--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--5e384ae7-672c-4250-9cda-3b4da964451a",
        "value": "lhc.lu"
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "value": "misp-project.org"
    }
]
_EMAIL_ADDRESS_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-addr--46f7e73f-36e5-40dd-9b27-735a0a6b44c2",
            "email-addr--49713b77-b6ee-4069-a1b4-2a8ad49adf62",
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-addr--81294150-8f7a-453d-a1d8-96c2cfe04efa"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--1bf81a4f-0e70-4a34-944b-7e46f67ff7a7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-addr--cd890f31-5825-4fea-85ca-0b3ab3872926"
        ]
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--46f7e73f-36e5-40dd-9b27-735a0a6b44c2",
        "value": "john.doe@gmail.com",
        "display_name": "John Doe"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--49713b77-b6ee-4069-a1b4-2a8ad49adf62",
        "value": "john@doe.org"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--81294150-8f7a-453d-a1d8-96c2cfe04efa",
        "value": "donald.duck@disney.com",
        "display_name": "Donald Duck"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--cd890f31-5825-4fea-85ca-0b3ab3872926",
        "value": "donald.duck@gmail.com"
    }
]
_FILE_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--5e384ae7-672c-4250-9cda-3b4da964451a",
            "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--1a165e68-ea72-44e6-b821-3b88f2cc46d8",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--b52bc0df-84e3-44bf-8a55-2889e26723fa",
            "file--5e384ae7-672c-4250-9cda-3b4da964451a",
            "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--6ee289fa-fe03-5ca5-bbdf-451603a31436"
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--5e384ae7-672c-4250-9cda-3b4da964451a",
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802",
            "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86",
            "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
        },
        "size": 35,
        "name": "oui",
        "name_enc": "UTF-8",
        "parent_directory_ref": "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    },
    {
        "type": "directory",
        "spec_version": "2.1",
        "id": "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "path": "/var/www/MISP/app/files/scripts/tmp"
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "mime_type": "application/zip",
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802"
        },
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected"
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--b52bc0df-84e3-44bf-8a55-2889e26723fa",
        "name": "oui.zip",
        "hashes": {
            "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
        },
        "mime_type": "application/zip",
        "extensions": {
            "archive-ext": {
                "comment": "Zip file containing `oui` in the tmp directory",
                "contains_refs": [
                    "file--5e384ae7-672c-4250-9cda-3b4da964451a",
                    "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
                ]
            }
        }
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--6ee289fa-fe03-5ca5-bbdf-451603a31436",
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
]
_INTRUSION_SET_OBJECTS = [
    {
        "type": "intrusion-set",
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "ipv6-addr--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "ipv4-addr--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "8.8.8.8"
    },
    {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": "ipv6-addr--5e384ae7-672c-4250-9cda-3b4da964451a",
        "value": "2001:4860:4860::8888"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "value": "185.194.93.14"
    }
]
_LOCATION_OBJECTS = [
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--84668357-5a8c-4bdd-9f0f-6b50b2535745",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "sweden",
        "description": "Sweden",
        "country": "SE"
    },
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Northern Europe",
        "description": "Nothern Europe",
        "region": "northern-europe"
    }
]
_MAC_ADDRESS_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "mac-addr--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mac-addr--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": "mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "d2:fb:49:24:37:18"
    },
    {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": "mac-addr--5e384ae7-672c-4250-9cda-3b4da964451a",
        "value": "62:3e:5f:53:ac:68"
    },
    {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": "mac-addr--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "value": "ae:49:db:d4:d9:cf"
    }
]
_MALWARE_OBJECTS = [
    {
        "type": "malware",
        "spec_version": "2.1",
        "is_family": True,
        "id": "malware--2485b844-4efe-4343-84c8-eb33312dd56f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MANITSME",
        "malware_types": [
            "backdoor",
            "dropper",
            "remote-access-trojan"
        ],
        "description": "This malware will beacon out at random intervals to the remote attacker. The attacker can run programs, execute arbitrary commands, and easily upload and download files."
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "is_family": True,
        "id": "malware--c0217091-9d3d-42a1-8952-ccc12d4ad8d0",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "WEBC2-UGX",
        "malware_types": [
            "backdoor",
            "remote-access-trojan"
        ],
        "description": "A WEBC2 backdoor is designed to retrieve a Web page from a C2 server. It expects the page to contain special HTML tags; the backdoor will attempt to interpret the data between the tags as commands."
    }
]
_MUTEX_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "mutex--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mutex--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "shared_resource_lock"
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--5e384ae7-672c-4250-9cda-3b4da964451a",
        "name": "thread_synchronization_lock"
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "name": "sensitive_resource_lock"
    }
]
_NETWORK_TRAFFIC_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
            "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
            "ipv4-addr--ffe65ce3-bf2a-577c-bb7e-947d39198637",
            "network-traffic--ac267abc-1a41-536d-8e8d-98458d9bf491",
            "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
            "ipv4-addr--f2d3c796-6c1a-5c4f-8516-d4db54727f89",
            "ipv4-addr--bb884ffe-f2e4-56bb-a0c3-21f6711cb649",
            "network-traffic--b4a8c150-e214-57a3-9017-e85dfa345f46",
            "network-traffic--65a6016d-a91c-5781-baad-178cd55f01d4"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
        "value": "198.51.100.2"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
        "value": "203.0.113.1"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--ffe65ce3-bf2a-577c-bb7e-947d39198637",
        "value": "203.0.113.2"
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--ac267abc-1a41-536d-8e8d-98458d9bf491",
        "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
        "dst_ref": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
        "src_port": 2487,
        "dst_port": 1723,
        "protocols": [
            "ipv4",
            "pptp"
        ],
        "src_byte_count": 35779,
        "dst_byte_count": 935750,
        "encapsulates_refs": [
            "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3"
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3",
        "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
        "dst_ref": "ipv4-addr--ffe65ce3-bf2a-577c-bb7e-947d39198637",
        "src_port": 24678,
        "dst_port": 80,
        "protocols": [
            "ipv4",
            "tcp",
            "http"
        ],
        "src_packets": 14356,
        "dst_packets": 14356,
        "encapsulated_by_ref": "network-traffic--ac267abc-1a41-536d-8e8d-98458d9bf491"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--f2d3c796-6c1a-5c4f-8516-d4db54727f89",
        "value": "198.51.100.34"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--bb884ffe-f2e4-56bb-a0c3-21f6711cb649",
        "value": "198.51.100.54"
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--b4a8c150-e214-57a3-9017-e85dfa345f46",
        "src_ref": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
        "dst_ref": "ipv4-addr--f2d3c796-6c1a-5c4f-8516-d4db54727f89",
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
            "network-traffic--65a6016d-a91c-5781-baad-178cd55f01d4"
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--65a6016d-a91c-5781-baad-178cd55f01d4",
        "src_ref": "ipv4-addr--f2d3c796-6c1a-5c4f-8516-d4db54727f89",
        "dst_ref": "ipv4-addr--bb884ffe-f2e4-56bb-a0c3-21f6711cb649",
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
        "encapsulated_by_ref": "network-traffic--b4a8c150-e214-57a3-9017-e85dfa345f46"
    }
]
_PROCESS_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "process--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "process--5e384ae7-672c-4250-9cda-3b4da964451a",
            "file--d1385ba1-69de-4774-879c-f2c4771b369d",
            "process--f93cb275-0366-4ecc-abf0-a17928d1e177",
            "file--43fdb7b9-a771-4b10-ab74-2bac893daf0d"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "process--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0"
        ]
    },
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "pid": 2510,
        "name": "TestProcess",
        "image_ref": "file--43fdb7b9-a771-4b10-ab74-2bac893daf0d",
        "parent_ref": "process--5e384ae7-672c-4250-9cda-3b4da964451a",
        "child_refs": [
            "process--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ],
        "is_hidden": True
    },
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--5e384ae7-672c-4250-9cda-3b4da964451a",
        "pid": 2107,
        "name": "Friends_From_H",
        "cwd": "/home/viktor",
        "created_time": "2017-05-01T08:00:00Z",
        "command_line": "grep -nrG iglocska ${HOME}/friends.txt",
        "environment_variables": {
            "HOME": "/home/viktor",
            "USER": "viktor"
        },
        "image_ref": "file--d1385ba1-69de-4774-879c-f2c4771b369d"
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--d1385ba1-69de-4774-879c-f2c4771b369d",
        "name": "parent_process.exe",
        "size": 12367,
        "name_enc": "UTF-8",
        "mime_type": "application/exe"
    },
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "pid": 1401,
        "name": "ChildProcess"
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--43fdb7b9-a771-4b10-ab74-2bac893daf0d",
        "name": "test_process.exe",
        "size": 82639,
        "name_enc": "UTF-8",
        "mime_type": "application/exe"
    },
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "pid": 666,
        "name": "SatanProcess",
        "command_line": "rm -rf *"
    }
]
_REGISTRY_KEY_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "windows-registry-key--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
            "user-account--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "key": "hkey_local_machine\\system\\bar\\baz",
        "modified_time": "2020-10-25T16:22:00Z",
        "values": [
            {
                "name": "RegistryName",
                "data": "%DATA%\\baz",
                "data_type": "REG_SZ"
            }
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
        "key": "hkey_local_machine\\system\\bar\\foo",
        "modified_time": "2020-10-25T16:22:00Z",
        "number_of_subkeys": 2,
        "creator_user_ref": "user-account--5e384ae7-672c-4250-9cda-3b4da964451a",
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
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "key": "hkey_local_machine\\system\\foo\\fortytwo",
        "modified_time": "2020-10-25T16:22:00Z",
        "creator_user_ref": "user-account--5e384ae7-672c-4250-9cda-3b4da964451a",
        "values": [
            {
                "name": "FortyTwoFoo",
                "data": "%DATA%\\42",
                "data_type": "REG_QWORD"
            }
        ]
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--5e384ae7-672c-4250-9cda-3b4da964451a",
        "user_id": "john.doe",
        "account_login": "JohnDoe",
        "account_type": "windows-local",
        "is_privileged": True
    }
]
_SOFTWARE_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "software--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "software--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "software--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "MISP",
        "languages": [
            "PHP"
        ],
        "vendor": "MISP Project",
        "version": "2.4.183"
    },
    {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--5e384ae7-672c-4250-9cda-3b4da964451a",
        "name": "misp-stix",
        "languages": [
            "Python"
        ],
        "vendor": "CIRCL",
        "spec_version": "2.1",
        "version": "2.4.183"
    },
    {
        "type": "software",
        "id": "software--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "spec_version": "2.1",
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
]
_THREAT_ACTOR_OBJECTS = [
    {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": "threat-actor--6d179234-61fc-40c4-ae86-3d53308d8e65",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Ugly Gorilla",
        "threat_actor_types": [
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
        "spec_version": "2.1",
        "id": "threat-actor--d84cf283-93be-4ca7-890d-76c63eff3636",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "DOTA",
        "threat_actor_types": [
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
        "spec_version": "2.1",
        "id": "tool--ce45f721-af14-4fc0-938c-000c16186418",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "cachedump",
        "tool_types": [
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
        "spec_version": "2.1",
        "id": "tool--e9778c42-bc2f-4eda-9fb4-6a931834f68c",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "fgdump",
        "tool_types": [
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
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "url--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "url--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "https://circl.lu/team/"
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--5e384ae7-672c-4250-9cda-3b4da964451a",
        "value": "https://cybersecurity.lu/entity/324"
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "value": "https://misp-project.org/blog/"
    }
]
_USER_ACCOUNT_OBJECTS = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
            "user-account--9bd3afcf-deee-54f9-83e2-520653cb6bba"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ]
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": False,
        "is_privileged": False,
        "can_escalate_privs": True,
        "account_created": "2016-01-20T12:31:12Z",
        "credential_last_changed": "2016-01-20T14:27:43Z",
        "account_first_login": "2016-01-20T14:26:07Z",
        "account_last_login": "2016-07-22T16:08:28Z"
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--9bd3afcf-deee-54f9-83e2-520653cb6bba",
        "user_id": "thegrugq_ebooks",
        "account_login": "thegrugq_ebooks",
        "account_type": "twitter",
        "display_name": "the grugq"
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
]
_VULNERABILITY_OBJECTS = [
    {
        "type": "vulnerability",
        "spec_version": "2.1",
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
        "spec_version": "2.1",
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
        "spec_version": "2.1",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "x509-certificate--5e384ae7-672c-4250-9cda-3b4da964451a"
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "x509-certificate--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--5e384ae7-672c-4250-9cda-3b4da964451a",
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
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--f93cb275-0366-4ecc-abf0-a17928d1e177",
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
]


class TestExternalSTIX21Bundles:
    __bundle = {
        "type": "bundle",
        "id": "bundle--314e4210-e41a-4952-9f3c-135d7d577112"
    }
    __identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00Z",
        "modified": "2020-10-25T16:22:00Z",
        "name": "MISP-Project",
        "identity_class": "organization"
    }
    __grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00Z",
        "modified": "2020-10-25T16:22:00Z",
        "name": "MISP-STIX-Converter test event",
        "context": "suspicious-activity",
        "labels": [
            "Threat-Report"
        ]
    }
    __indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
            deepcopy(cls.__identity), deepcopy(cls.__grouping), *stix_objects
        ]
        bundle['objects'][1]['object_refs'] = [
            stix_object['id'] for stix_object in stix_objects
        ]
        return dict_to_stix2(bundle, allow_custom=True)

    @classmethod
    def __assemble_galaxy_bundle(cls, event_galaxy, attribute_galaxy):
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7cede760-b866-490e-ad5b-1df34bc14f8d",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "relationship_type": "indicates",
            "source_ref": cls.__indicator['id'],
            "target_ref": attribute_galaxy['id']
        }
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            deepcopy(cls.__identity), deepcopy(cls.__grouping),
            event_galaxy, cls.__indicator, attribute_galaxy, relationship
        ]
        bundle['objects'][1]['object_refs'] = [
            stix_object['id'] for stix_object in bundle['objects'][2:]
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
    def get_bundle_with_location_galaxy(cls):
        return cls.__assemble_galaxy_bundle(*_LOCATION_OBJECTS)

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
    def get_bundle_with_email_address_attributes(cls):
        return cls.__assemble_bundle(*_EMAIL_ADDRESS_ATTRIBUTES)

    @classmethod
    def get_bundle_with_file_objects(cls):
        observables = deepcopy(_FILE_OBJECTS)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observables[-3]['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(*observables)

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
    def get_bundle_with_opinion_objects(cls):
        agree_opinion = {
            "type": "opinion",
            "spec_version": "2.1",
            "id": "opinion--3b7f3754-a31c-4bf8-a97f-a8ff10aab5a3",
            "created_by_ref": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
            "created": "2024-02-17T00:47:42.000Z",
            "modified": "2024-02-17T00:47:42.000Z",
            "opinion": "agree",
            "explanation": "Not confirmed; possibly malicious (if marked or otherwise evaluated as malicious-activity) or benign (if marked as benign); no other information on the subject known to the opinion author. Please see AIS Scoring Framework used for Indicator Enrichment at https://www.cisa.gov/ais.",
            "object_refs": [
                "observed-data--e812789e-e49d-47e2-b334-8ee0e8a766ce"
            ]
        }
        strongly_disagree_opinion = {
            "type": "opinion",
            "spec_version": "2.1",
            "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "opinion": "strongly-disagree",
            "explanation": "This doesn't seem like it is feasible.",
            "object_refs": [
                "software--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
            ]
        }
        return cls.__assemble_bundle(
            agree_opinion, strongly_disagree_opinion,
            deepcopy(_DIRECTORY_OBJECTS[1]), deepcopy(_SOFTWARE_OBJECTS[0]),
            deepcopy(_DIRECTORY_OBJECTS[-1]), *deepcopy(_SOFTWARE_OBJECTS[2:-1])
        )

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
