# External STIX 2.1 to MISP Galaxies mapping

When importing STIX 2.1 bundles from third-party tools (not produced by MISP), SDOs such as `Attack Pattern`, `Campaign`, `Course of Action`, `Intrusion Set`, `Location`, `Malware`, `Threat Actor`, `Tool` and `Vulnerability` are imported as MISP Galaxy Clusters with a dynamically generated galaxy type of the form `stix-2.1-{object-type}`.

Unlike the internal conversion (which maps back to known MISP galaxy types), the external conversion creates new `STIX 2.1 *` galaxies that preserve the original STIX content. The cluster value is the STIX object's `name`, and meta fields are extracted from fields such as `aliases`, `kill_chain_phases`, `external_references`, etc.

- attack-pattern
  - STIX
    ```json
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--19da6e1c-69a8-4c2f-886d-d620d09d3b5a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Spear Phishing Attack Pattern used by admin@338",
        "description": "The preferred attack vector used by admin@338 is spear-phishing emails. Using content that is relevant to the target, these emails are designed to entice the target to open an attachment that contains the malicious PIVY server code.",
        "aliases": [
            "Spear Phishing"
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "initial-compromise"
            }
        ],
        "external_references": [
            {
                "source_name": "capec",
                "description": "spear phishing",
                "external_id": "CAPEC-163"
            }
        ]
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "synonyms",
                        "value": "Spear Phishing"
                    },
                    {
                        "key": "external_id",
                        "value": "CAPEC-163"
                    },
                    {
                        "key": "kill_chain",
                        "value": "mandiant-attack-lifecycle-model:initial-compromise"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "synonyms": [
                        "Spear Phishing"
                    ],
                    "external_id": "CAPEC-163",
                    "kill_chain": [
                        "mandiant-attack-lifecycle-model:initial-compromise"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "ef6eb51e-e601-5d4f-8aad-124c4f5507b0",
                "value": "Spear Phishing Attack Pattern used by admin@338",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "9be38d88-6e00-570b-b6c9-0076006ffb61",
                "type": "stix-2.1-attack-pattern",
                "description": "The preferred attack vector used by admin@338 is spear-phishing emails. Using content that is relevant to the target, these emails are designed to entice the target to open an attachment that contains the malicious PIVY server code."
            }
        ],
        "description": "Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "9be38d88-6e00-570b-b6c9-0076006ffb61",
        "version": "21",
        "icon": "map",
        "type": "stix-2.1-attack-pattern",
        "name": "STIX 2.1 Attack Pattern"
    }
    ```

- campaign
  - STIX
    ```json
    {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--752c225d-d6f6-4456-9130-d9580fd4007b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "RRN",
        "description": "Active since 2008, this campaign mostly targets the financial services industry, though we have also seen activity in the telecom, government, and defense sectors.",
        "aliases": [
            "Doppelganger"
        ],
        "first_seen": "2020-10-25T16:22:00Z",
        "objective": "manipulation"
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "first_seen",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "synonyms",
                        "value": "Doppelganger"
                    },
                    {
                        "key": "objective",
                        "value": "manipulation"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "first_seen": "2020-10-25T16:22:00Z",
                    "synonyms": [
                        "Doppelganger"
                    ],
                    "objective": "manipulation"
                },
                "default": false,
                "distribution": "0",
                "uuid": "0dd0896b-8834-5025-a4d4-c0f4bbf7d403",
                "value": "RRN",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "3d29c2ad-cb5a-5173-8ef6-1afd3bd2ed34",
                "type": "stix-2.1-campaign",
                "description": "Active since 2008, this campaign mostly targets the financial services industry, though we have also seen activity in the telecom, government, and defense sectors."
            }
        ],
        "description": "A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "3d29c2ad-cb5a-5173-8ef6-1afd3bd2ed34",
        "version": "21",
        "icon": "user-secret",
        "type": "stix-2.1-campaign",
        "name": "STIX 2.1 Campaign"
    }
    ```

- course-of-action
  - STIX
    ```json
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
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "refs",
                        "value": "https://github.com/fireeye/chopshop"
                    },
                    {
                        "key": "refs",
                        "value": "https://github.com/fireeye/pycommands"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "refs": [
                        "https://github.com/fireeye/chopshop",
                        "https://github.com/fireeye/pycommands"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "47b461bd-0d5a-5cbc-96de-31515356f087",
                "value": "Analyze with FireEye Calamine Toolset",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "e0b51d22-4971-5444-879c-317f5bfa959e",
                "type": "stix-2.1-course-of-action",
                "description": "Calamine is a set of free tools to help organizations detect and examine Poison Ivy infections on their systems. The package includes these components: PIVY callback-decoding tool (ChopShop Module) and PIVY memory-decoding tool (PIVY PyCommand Script)."
            }
        ],
        "description": "A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "e0b51d22-4971-5444-879c-317f5bfa959e",
        "version": "21",
        "icon": "link",
        "type": "stix-2.1-course-of-action",
        "name": "STIX 2.1 Course of Action"
    }
    ```

- intrusion-set
  - STIX
    ```json
    {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": "intrusion-set--da1065ce-972c-4605-8755-9cd1074e3b5a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "APT1",
        "description": "APT1 is a single organization of operators that has conducted a cyber espionage campaign against a broad range of victims since at least 2006.",
        "aliases": [
            "Comment Crew",
            "Comment Group",
            "Shady Rat"
        ],
        "first_seen": "2020-10-25T16:22:00Z",
        "goals": [
            "Gather information on victims"
        ],
        "resource_level": "government",
        "primary_motivation": "organizational-gain"
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "first_seen",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "synonyms",
                        "value": "Comment Crew"
                    },
                    {
                        "key": "synonyms",
                        "value": "Comment Group"
                    },
                    {
                        "key": "synonyms",
                        "value": "Shady Rat"
                    },
                    {
                        "key": "goals",
                        "value": "Gather information on victims"
                    },
                    {
                        "key": "primary_motivation",
                        "value": "organizational-gain"
                    },
                    {
                        "key": "resource_level",
                        "value": "government"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "first_seen": "2020-10-25T16:22:00Z",
                    "synonyms": [
                        "Comment Crew",
                        "Comment Group",
                        "Shady Rat"
                    ],
                    "goals": [
                        "Gather information on victims"
                    ],
                    "primary_motivation": "organizational-gain",
                    "resource_level": "government"
                },
                "default": false,
                "distribution": "0",
                "uuid": "86ddf25a-5c34-52c8-a9c3-07a06f3cc5d3",
                "value": "APT1",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "7205e3fa-e1eb-5215-a68f-35ab2b4eb87d",
                "type": "stix-2.1-intrusion-set",
                "description": "APT1 is a single organization of operators that has conducted a cyber espionage campaign against a broad range of victims since at least 2006."
            }
        ],
        "description": "An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown Threat Actor.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "7205e3fa-e1eb-5215-a68f-35ab2b4eb87d",
        "version": "21",
        "icon": "user-secret",
        "type": "stix-2.1-intrusion-set",
        "name": "STIX 2.1 Intrusion Set"
    }
    ```

- location
  - STIX
    ```json
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--84668357-5a8c-4bdd-9f0f-6b50b2535745",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "sweden",
        "description": "Sweden",
        "region": "northern-europe",
        "country": "SE"
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "country",
                        "value": "SE"
                    },
                    {
                        "key": "region",
                        "value": "northern-europe"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "country": "SE",
                    "region": "northern-europe"
                },
                "default": false,
                "distribution": "0",
                "uuid": "39dbb684-98cd-579b-9683-c7a2c311de14",
                "value": "sweden",
                "source": "misp-stix",
                "version": "21",
                "collection_uuid": "4f858bdf-8213-5d43-999b-d22c2074983d",
                "type": "stix-2.1-location",
                "description": "Sweden"
            }
        ],
        "description": "A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "4f858bdf-8213-5d43-999b-d22c2074983d",
        "version": "21",
        "icon": "globe",
        "type": "stix-2.1-location",
        "name": "STIX 2.1 Location"
    }
    ```

- malware
  - STIX
    ```json
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--2485b844-4efe-4343-84c8-eb33312dd56f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MANITSME",
        "description": "This malware will beacon out at random intervals to the remote attacker. The attacker can run programs, execute arbitrary commands, and easily upload and download files.",
        "malware_types": [
            "backdoor",
            "dropper",
            "remote-access-trojan"
        ],
        "is_family": true,
        "aliases": [
            "ManItsMe"
        ],
        "first_seen": "2020-10-25T16:22:00Z",
        "architecture_execution_envs": [
            "x86-64"
        ],
        "implementation_languages": [
            "c++"
        ],
        "capabilities": [
            "accesses-remote-machines",
            "communicates-with-c2"
        ]
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "first_seen",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "synonyms",
                        "value": "ManItsMe"
                    },
                    {
                        "key": "architecture_execution_envs",
                        "value": "x86-64"
                    },
                    {
                        "key": "capabilities",
                        "value": "accesses-remote-machines"
                    },
                    {
                        "key": "capabilities",
                        "value": "communicates-with-c2"
                    },
                    {
                        "key": "implementation_languages",
                        "value": "c++"
                    },
                    {
                        "key": "is_family",
                        "value": true
                    },
                    {
                        "key": "malware_types",
                        "value": "backdoor"
                    },
                    {
                        "key": "malware_types",
                        "value": "dropper"
                    },
                    {
                        "key": "malware_types",
                        "value": "remote-access-trojan"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "first_seen": "2020-10-25T16:22:00Z",
                    "synonyms": [
                        "ManItsMe"
                    ],
                    "architecture_execution_envs": [
                        "x86-64"
                    ],
                    "capabilities": [
                        "accesses-remote-machines",
                        "communicates-with-c2"
                    ],
                    "implementation_languages": [
                        "c++"
                    ],
                    "is_family": true,
                    "malware_types": [
                        "backdoor",
                        "dropper",
                        "remote-access-trojan"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "d7ec91c0-e001-5992-9258-b0147fc71014",
                "value": "MANITSME",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "5de9a83d-06f0-532b-bcf6-54eaf4db61c8",
                "type": "stix-2.1-malware",
                "description": "This malware will beacon out at random intervals to the remote attacker. The attacker can run programs, execute arbitrary commands, and easily upload and download files."
            }
        ],
        "description": "Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly. The intent is to compromise the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or otherwise annoy or disrupt the victim.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "5de9a83d-06f0-532b-bcf6-54eaf4db61c8",
        "version": "21",
        "icon": "optin-monster",
        "type": "stix-2.1-malware",
        "name": "STIX 2.1 Malware"
    }
    ```

- threat-actor
  - STIX
    ```json
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
        "aliases": [
            "Greenfield",
            "JackWang",
            "Wang Dong"
        ],
        "roles": [
            "malware-author",
            "agent",
            "infrastructure-operator"
        ],
        "resource_level": "government",
        "primary_motivation": "organizational-gain"
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "synonyms",
                        "value": "Greenfield"
                    },
                    {
                        "key": "synonyms",
                        "value": "JackWang"
                    },
                    {
                        "key": "synonyms",
                        "value": "Wang Dong"
                    },
                    {
                        "key": "primary_motivation",
                        "value": "organizational-gain"
                    },
                    {
                        "key": "resource_level",
                        "value": "government"
                    },
                    {
                        "key": "roles",
                        "value": "malware-author"
                    },
                    {
                        "key": "roles",
                        "value": "agent"
                    },
                    {
                        "key": "roles",
                        "value": "infrastructure-operator"
                    },
                    {
                        "key": "threat_actor_types",
                        "value": "nation-state"
                    },
                    {
                        "key": "threat_actor_types",
                        "value": "spy"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "synonyms": [
                        "Greenfield",
                        "JackWang",
                        "Wang Dong"
                    ],
                    "primary_motivation": "organizational-gain",
                    "resource_level": "government",
                    "roles": [
                        "malware-author",
                        "agent",
                        "infrastructure-operator"
                    ],
                    "threat_actor_types": [
                        "nation-state",
                        "spy"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "68f82328-1545-54eb-9f75-bfc6967c172c",
                "value": "Ugly Gorilla",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "69073dcd-d569-5589-81a0-e1a36ec7c3f0",
                "type": "stix-2.1-threat-actor",
                "description": "Ugly gorilla"
            }
        ],
        "description": "Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or be affiliated with various Intrusion Sets, groups, or organizations over time.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "69073dcd-d569-5589-81a0-e1a36ec7c3f0",
        "version": "21",
        "icon": "user-secret",
        "type": "stix-2.1-threat-actor",
        "name": "STIX 2.1 Threat Actor"
    }
    ```

- tool
  - STIX
    ```json
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--ce45f721-af14-4fc0-938c-000c16186418",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "cachedump",
        "description": "This program extracts cached password hashes from a system\u2019s registry.",
        "tool_types": [
            "credential-exploitation"
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mandiant-attack-lifecycle-model",
                "phase_name": "escalate-privileges"
            }
        ]
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "tool_types",
                        "value": "credential-exploitation"
                    },
                    {
                        "key": "kill_chain",
                        "value": "mandiant-attack-lifecycle-model:escalate-privileges"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "tool_types": [
                        "credential-exploitation"
                    ],
                    "kill_chain": [
                        "mandiant-attack-lifecycle-model:escalate-privileges"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "217ddd14-44cd-5366-a5db-3682cec9feb6",
                "value": "cachedump",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "77e81218-13f5-537a-acfa-caf14fbe1810",
                "type": "stix-2.1-tool",
                "description": "This program extracts cached password hashes from a system\u2019s registry."
            }
        ],
        "description": "Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "77e81218-13f5-537a-acfa-caf14fbe1810",
        "version": "21",
        "icon": "gavel",
        "type": "stix-2.1-tool",
        "name": "STIX 2.1 Tool"
    }
    ```

- vulnerability
  - STIX
    ```json
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
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "GalaxyElement": [
                    {
                        "key": "created",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "modified",
                        "value": "2020-10-25T16:22:00Z"
                    },
                    {
                        "key": "external_id",
                        "value": "CVE-2012-0158"
                    }
                ],
                "meta": {
                    "created": "2020-10-25T16:22:00Z",
                    "modified": "2020-10-25T16:22:00Z",
                    "external_id": "CVE-2012-0158"
                },
                "default": false,
                "distribution": "0",
                "uuid": "bb3e1fa5-7ccd-5b9e-b5da-b1981d0b39ac",
                "value": "CVE-2012-0158",
                "source": "MISP-Project",
                "version": "21",
                "collection_uuid": "90ec1934-1ab3-5f62-a526-53a5f7f61b90",
                "type": "stix-2.1-vulnerability",
                "description": "Weaponized Microsoft Word document used by admin@338"
            }
        ],
        "description": "A Vulnerability is a weakness or defect in the requirements, designs, or implementations of the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that can be directly exploited to negatively impact the confidentiality, integrity, or availability of that system.",
        "namespace": "stix",
        "distribution": "0",
        "uuid": "90ec1934-1ab3-5f62-a526-53a5f7f61b90",
        "version": "21",
        "icon": "bug",
        "type": "stix-2.1-vulnerability",
        "name": "STIX 2.1 Vulnerability"
    }
    ```


## The other detailed mappings

For more detailed mappings, click on one of the links below:
- [Attributes import from STIX 2.1 mapping](stix21_to_misp_attributes.md)
- [Objects import from STIX 2.1 mapping](stix21_to_misp_objects.md)

([Go back to the main documentation](README.md))
