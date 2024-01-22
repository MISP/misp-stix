#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
from stix2.parsing import dict_to_stix2


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
    def get_bundle_with_ip_address_attributes(cls):
        return cls.__assemble_bundle(*_IP_ADDRESS_ATTRIBUTES)

    @classmethod
    def get_bundle_with_mac_address_attributes(cls):
        return cls.__assemble_bundle(*_MAC_ADDRESS_ATTRIBUTES)

    @classmethod
    def get_bundle_with_mutex_attributes(cls):
        return cls.__assemble_bundle(*_MUTEX_ATTRIBUTES)

    @classmethod
    def get_bundle_with_url_attributes(cls):
        return cls.__assemble_bundle(*_URL_ATTRIBUTES)
