# MISP Galaxies to STIX 2.1 mapping

MISP galaxies are exported in `Attack Pattern`, `Course of Action`, `Malware`, `Threat Actor`, `Tool` or `Vulnerability` objects.

Sometimes 2 different Galaxies are mapped into the same STIX 2.1 object, the following examples don't show each Galaxy type, but only one for each resulting STIX object. If you want to see the complete mapping, the [MISP Galaxies to STIX 2.0 mapping summary](README.md#Galaxies-to-STIX-20-mapping) gives all the Galaxy types that are mapped into each STIX object type

Since not all the fields of the galaxies and their clusters are exported into STIX 2.1, the following examples are given with the fields that are exported only, if you want to have a look at the full definitions, you can visit the [MISP Galaxies repository](https://github.com/MISP/misp-galaxy).

- Attack Pattern
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "Access Token Manipulation - T1134",
        "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "mitre-attack-pattern"
            }
        ],
        "labels": [
            "misp:name=\"Attack Pattern\""
        ],
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-633"
            }
        ]
    }
    ```

- Branded Vulnerability
  - MISP
    ```json
    {
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
                        "CVE-2015-0235"
                    ]
                }
            }
        ]
    }
    ```
  - STIX
    ```json
    {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": "vulnerability--a1640081-aa8d-4070-84b2-d23e2ae82799",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "Ghost",
        "description": "List of known vulnerabilities and exploits | The GHOST vulnerability is a serious weakness in the Linux glibc library.",
        "labels": [
            "misp:name=\"Branded Vulnerability\""
        ],
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2015-0235"
            }
        ]
    }
    ```

- Course of Action
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation - T1020",
        "description": "ATT&CK Mitigation | Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
        "labels": [
            "misp:name=\"Course of Action\""
        ]
    }
    ```

- Malware
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "BISCUIT - S0017",
        "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": true,
        "aliases": [
            "BISCUIT"
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "mitre-malware"
            }
        ],
        "labels": [
            "misp:name=\"Malware\""
        ]
    }
    ```

- Threat Actor
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": "threat-actor--11e17436-6ede-4733-8547-4ce0254ea19e",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "Cutting Kitten",
        "description": "Threat actors are characteristics of malicious actors. | These convincing profiles form a self-referenced network of seemingly established LinkedIn users.",
        "aliases": [
            "Ghambar"
        ],
        "labels": [
            "misp:name=\"Threat Actor\""
        ]
    }
    ```

- Tool
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
        "created": "2020-25-10:16:22:00.000Z",
        "modified": "2020-25-10:16:22:00.000Z",
        "name": "cmd - S0106",
        "description": "Name of ATT&CK software | cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
        "aliases": [
            "cmd.exe"
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "mitre-tool"
            }
        ],
        "labels": [
            "misp:name=\"Tool\""
        ]
    }
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX 2.1 mapping](misp_events_to_stix21.md)
- [Attributes export to STIX 2.1 mapping](misp_attributes_to_stix21.md)
- [Objects export to STIX 2.1 mapping](misp_objects_to_stix21.md)

([Go back to the main documentation](README.md))
