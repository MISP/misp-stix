#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
from stix2.parsing import dict_to_stix2


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

    ################################################################################
    #                               GALAXIES SAMPLES                               #
    ################################################################################

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
