# STIX 2.0 to MISP Galaxies mapping

STIX 2.0 SDOs such as `Attack Pattern`, `Course of Action`, `Intrusion Set`, `Malware`, `Threat Actor`, `Tool` and `Vulnerability` are imported as MISP Galaxy Clusters.

The following examples show one STIX 2.0 object type per entry. Since MISP Galaxies contain rich metadata beyond what is stored in STIX objects, the examples show only the fields that are mapped during import.

- attack-pattern
  - STIX
    ```json
    {
        "type": "attack-pattern",
        "id": "attack-pattern--e042a41b-5ecf-4f3a-8f1f-1b528c534772",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Access Token Manipulation",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "defense-evasion"
            },
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "privilege-escalation"
            }
        ],
        "labels": [
            "misp:galaxy-name=\"Attack Pattern\"",
            "misp:galaxy-type=\"mitre-attack-pattern\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1134"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/techniques/T1134"
            }
        ],
        "x_misp_mitre_platforms": [
            "Windows"
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
                        "key": "mitre_platforms",
                        "value": "Windows"
                    },
                    {
                        "key": "refs",
                        "value": "https://attack.mitre.org/techniques/T1134"
                    },
                    {
                        "key": "external_id",
                        "value": "T1134"
                    },
                    {
                        "key": "kill_chain",
                        "value": "mitre-attack:defense-evasion"
                    },
                    {
                        "key": "kill_chain",
                        "value": "mitre-attack:privilege-escalation"
                    }
                ],
                "meta": {
                    "mitre_platforms": [
                        "Windows"
                    ],
                    "refs": [
                        "https://attack.mitre.org/techniques/T1134"
                    ],
                    "external_id": "T1134",
                    "kill_chain": [
                        "mitre-attack:defense-evasion",
                        "mitre-attack:privilege-escalation"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "e042a41b-5ecf-4f3a-8f1f-1b528c534772",
                "value": "Access Token Manipulation - T1134",
                "type": "mitre-attack-pattern",
                "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls."
            }
        ],
        "description": "ATT&CK Tactic",
        "icon": "map",
        "name": "Attack Pattern",
        "namespace": "mitre-attack",
        "type": "mitre-attack-pattern",
        "uuid": "c4e851fa-775f-11e7-8163-b774922098cd"
    }
    ```

- course-of-action
  - STIX
    ```json
    {
        "type": "course-of-action",
        "id": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation",
        "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
        "labels": [
            "misp:galaxy-name=\"Course of Action\"",
            "misp:galaxy-type=\"mitre-course-of-action\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1020"
            },
            {
                "source_name": "url",
                "url": "https://apps.nsa.gov/iaarchive/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/mitigations/T1020"
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
                        "key": "refs",
                        "value": "https://apps.nsa.gov/iaarchive/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm"
                    },
                    {
                        "key": "refs",
                        "value": "https://attack.mitre.org/mitigations/T1020"
                    },
                    {
                        "key": "external_id",
                        "value": "T1020"
                    }
                ],
                "meta": {
                    "refs": [
                        "https://apps.nsa.gov/iaarchive/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm",
                        "https://attack.mitre.org/mitigations/T1020"
                    ],
                    "external_id": "T1020"
                },
                "default": false,
                "distribution": "0",
                "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
                "value": "Automated Exfiltration Mitigation - T1020",
                "type": "mitre-course-of-action",
                "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
            }
        ],
        "description": "ATT&CK Mitigation",
        "icon": "link",
        "name": "Course of Action",
        "namespace": "mitre-attack",
        "type": "mitre-course-of-action",
        "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e"
    }
    ```

- identity
  - STIX
    ```json
    {
        "type": "identity",
        "id": "identity--75597b7f-54e8-4f14-88c9-e81485ece483",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "IT - Security",
        "description": "Activity sectors",
        "identity_class": "class",
        "labels": [
            "misp:galaxy-name=\"Sector\"",
            "misp:galaxy-type=\"sector\""
        ]
    }
    ```
  - MISP
    ```json
    {
        "GalaxyCluster": [
            {
                "meta": {},
                "default": false,
                "distribution": "0",
                "uuid": "75597b7f-54e8-4f14-88c9-e81485ece483",
                "value": "IT - Security",
                "type": "sector",
                "description": "Activity sectors"
            }
        ],
        "description": "Activity sectors",
        "icon": "industry",
        "name": "Sector",
        "namespace": "misp",
        "type": "sector",
        "uuid": "e1bb134c-ae4d-11e7-8aa9-f78a37325439"
    }
    ```

- intrusion-set
  - STIX
    ```json
    {
        "type": "intrusion-set",
        "id": "intrusion-set--d6e88e18-81e8-4709-82d8-973095da1e70",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "APT16",
        "description": "APT16 is a China-based threat group that has launched spearphishing campaigns targeting Japanese and Taiwanese organizations.",
        "labels": [
            "misp:galaxy-name=\"Intrusion Set\"",
            "misp:galaxy-type=\"mitre-intrusion-set\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "G0023"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/groups/G0023"
            },
            {
                "source_name": "url",
                "url": "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html"
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
                        "key": "refs",
                        "value": "https://attack.mitre.org/groups/G0023"
                    },
                    {
                        "key": "refs",
                        "value": "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html"
                    },
                    {
                        "key": "external_id",
                        "value": "G0023"
                    },
                    {
                        "key": "synonyms",
                        "value": "APT16"
                    }
                ],
                "meta": {
                    "refs": [
                        "https://attack.mitre.org/groups/G0023",
                        "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html"
                    ],
                    "external_id": "G0023",
                    "synonyms": [
                        "APT16"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "d6e88e18-81e8-4709-82d8-973095da1e70",
                "value": "APT16 - G0023",
                "type": "mitre-intrusion-set",
                "description": "APT16 is a China-based threat group that has launched spearphishing campaigns targeting Japanese and Taiwanese organizations."
            }
        ],
        "description": "Name of ATT&CK Group",
        "icon": "user-secret",
        "name": "Intrusion Set",
        "namespace": "mitre-attack",
        "type": "mitre-intrusion-set",
        "uuid": "1023f364-7831-11e7-8318-43b5531983ab"
    }
    ```

- malware
  - STIX
    ```json
    {
        "type": "malware",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT",
        "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "labels": [
            "misp:galaxy-name=\"Malware\"",
            "misp:galaxy-type=\"mitre-malware\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "S0017"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/software/S0017"
            },
            {
                "source_name": "url",
                "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
            }
        ],
        "x_misp_mitre_platforms": [
            "Windows"
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
                        "key": "mitre_platforms",
                        "value": "Windows"
                    },
                    {
                        "key": "refs",
                        "value": "https://attack.mitre.org/software/S0017"
                    },
                    {
                        "key": "refs",
                        "value": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
                    },
                    {
                        "key": "external_id",
                        "value": "S0017"
                    },
                    {
                        "key": "synonyms",
                        "value": "BISCUIT"
                    }
                ],
                "meta": {
                    "mitre_platforms": [
                        "Windows"
                    ],
                    "refs": [
                        "https://attack.mitre.org/software/S0017",
                        "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
                    ],
                    "external_id": "S0017",
                    "synonyms": [
                        "BISCUIT"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "b8eb28e4-48a6-40ae-951a-328714f75eda",
                "value": "BISCUIT - S0017",
                "type": "mitre-malware",
                "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007."
            }
        ],
        "description": "Name of ATT&CK software",
        "icon": "optin-monster",
        "name": "Malware",
        "namespace": "mitre-attack",
        "type": "mitre-malware",
        "uuid": "d752161c-78f6-11e7-a0ea-bfa79b407ce4"
    }
    ```

- threat-actor
  - STIX
    ```json
    {
        "type": "threat-actor",
        "id": "threat-actor--11e17436-6ede-4733-8547-4ce0254ea19e",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Cutting Kitten",
        "description": "These convincing profiles form a self-referenced network of seemingly established LinkedIn users.",
        "aliases": [
            "Ghambar"
        ],
        "labels": [
            "misp:galaxy-name=\"Threat Actor\"",
            "misp:galaxy-type=\"threat-actor\""
        ],
        "x_misp_cfr_type_of_incident": [
            "Denial of service"
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
                        "key": "synonyms",
                        "value": "Ghambar"
                    },
                    {
                        "key": "cfr-type-of-incident",
                        "value": "Denial of service"
                    }
                ],
                "meta": {
                    "synonyms": [
                        "Ghambar"
                    ],
                    "cfr-type-of-incident": [
                        "Denial of service"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "11e17436-6ede-4733-8547-4ce0254ea19e",
                "value": "Cutting Kitten",
                "type": "threat-actor",
                "description": "These convincing profiles form a self-referenced network of seemingly established LinkedIn users."
            }
        ],
        "description": "Threat actors are characteristics of malicious actors (or adversaries) representing a cyber attack threat including presumed intent and historically observed behaviour.",
        "icon": "user-secret",
        "name": "Threat Actor",
        "namespace": "misp",
        "type": "threat-actor",
        "uuid": "698774c7-8022-42c4-917f-8d6e4f06ada3"
    }
    ```

- tool
  - STIX
    ```json
    {
        "type": "tool",
        "id": "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "cmd",
        "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
        "labels": [
            "misp:galaxy-name=\"Tool\"",
            "misp:galaxy-type=\"mitre-tool\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "S0106"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/software/S0106"
            },
            {
                "source_name": "url",
                "url": "https://technet.microsoft.com/en-us/library/bb490880.aspx"
            }
        ],
        "x_misp_mitre_platforms": [
            "Windows"
        ],
        "x_misp_synonyms": [
            "cmd.exe",
            "cmd"
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
                        "key": "mitre_platforms",
                        "value": "Windows"
                    },
                    {
                        "key": "synonyms",
                        "value": "cmd.exe"
                    },
                    {
                        "key": "synonyms",
                        "value": "cmd"
                    },
                    {
                        "key": "refs",
                        "value": "https://attack.mitre.org/software/S0106"
                    },
                    {
                        "key": "refs",
                        "value": "https://technet.microsoft.com/en-us/library/bb490880.aspx"
                    },
                    {
                        "key": "external_id",
                        "value": "S0106"
                    }
                ],
                "meta": {
                    "mitre_platforms": [
                        "Windows"
                    ],
                    "synonyms": [
                        "cmd.exe",
                        "cmd"
                    ],
                    "refs": [
                        "https://attack.mitre.org/software/S0106",
                        "https://technet.microsoft.com/en-us/library/bb490880.aspx"
                    ],
                    "external_id": "S0106"
                },
                "default": false,
                "distribution": "0",
                "uuid": "bba595da-b73a-4354-aa6c-224d4de7cb4e",
                "value": "cmd - S0106",
                "type": "mitre-tool",
                "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities."
            }
        ],
        "description": "Name of ATT&CK software",
        "icon": "gavel",
        "name": "mitre-tool",
        "namespace": "mitre-attack",
        "type": "mitre-tool",
        "uuid": "d5cbd1a2-78f6-11e7-a833-7b9bccca9649"
    }
    ```

- vulnerability
  - STIX
    ```json
    {
        "type": "vulnerability",
        "id": "vulnerability--a1640081-aa8d-4070-84b2-d23e2ae82799",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Ghost",
        "description": "The GHOST vulnerability is a serious weakness in the Linux glibc library.",
        "labels": [
            "misp:galaxy-name=\"Branded Vulnerability\"",
            "misp:galaxy-type=\"branded-vulnerability\""
        ],
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2015-0235"
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
                        "key": "aliases",
                        "value": "CVE-2015-0235"
                    }
                ],
                "meta": {
                    "aliases": [
                        "CVE-2015-0235"
                    ]
                },
                "default": false,
                "distribution": "0",
                "uuid": "a1640081-aa8d-4070-84b2-d23e2ae82799",
                "value": "Ghost",
                "type": "branded-vulnerability",
                "description": "The GHOST vulnerability is a serious weakness in the Linux glibc library."
            }
        ],
        "description": "List of known vulnerabilities and exploits",
        "icon": "bug",
        "name": "Branded Vulnerability",
        "namespace": "misp",
        "type": "branded-vulnerability",
        "uuid": "fda8c7c2-f45a-11e7-9713-e75dac0492df"
    }
    ```


## The other detailed mappings

For more detailed mappings, click on one of the links below:
- [Attributes import from STIX 2.0 mapping](stix20_to_misp_attributes.md)
- [Objects import from STIX 2.0 mapping](stix20_to_misp_objects.md)

([Go back to the main documentation](README.md))
