# MISP Galaxies to STIX1 mapping

MISP galaxies are exported to STIX as `Course of Action`, `Threat actor` or as one of the different fields embedded within `TTPs`.

Sometimes 2 different Galaxies are mapped into the same STIX1 object, the following examples don't show each Galaxy type, but only one for each resulting STIX object. If you want to see the complete mapping, the [MISP Galaxies to STIX1 mapping summary](README.md#Galaxies-to-STIX1-mapping) gives all the Galaxy types that are mapped into each STIX object type

Since not all the fields of the galaxies and their clusters are exported into STIX1, the following examples are given with the fields that are exported only, if you want to have a look at the full definitions, you can visit the [MISP Galaxies repository](https://github.com/MISP/misp-galaxy).

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
    ```xml
    <ttp:TTP id="MISP:TTP-dcaa092b-7de9-4a21-977f-7fcb77e89c48" timestamp="2020-11-21T12:46:33.151602+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>Attack Pattern (MISP Galaxy)</ttp:Title>
        <ttp:Behavior>
            <ttp:Attack_Patterns>
                <ttp:Attack_Pattern capec_id="CAPEC-633" id="MISP:AttackPattern-dcaa092b-7de9-4a21-977f-7fcb77e89c48">
                    <ttp:Title>Access Token Manipulation - T1134</ttp:Title>
                    <ttp:Description>Windows uses access tokens to determine the ownership of a running process.</ttp:Description>
                </ttp:Attack_Pattern>
            </ttp:Attack_Patterns>
        </ttp:Behavior>
    </ttp:TTP>
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
    ```xml
    <ttp:TTP id="MISP:TTP-a1640081-aa8d-4070-84b2-d23e2ae82799" timestamp="2020-11-21T12:46:33.159077+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>Branded Vulnerability (MISP Galaxy)</ttp:Title>
        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target id="MISP:ExploitTarget-a1640081-aa8d-4070-84b2-d23e2ae82799" timestamp="2020-11-21T12:46:33.159137+00:00" xsi:type='et:ExploitTargetType'>
                    <et:Vulnerability>
                        <et:Title>Ghost</et:Title>
                        <et:Description>The GHOST vulnerability is a serious weakness in the Linux glibc library.</et:Description>
                        <et:CVE_ID>CVE-2015-0235</et:CVE_ID>
                    </et:Vulnerability>
                </stixCommon:Exploit_Target>
            </ttp:Exploit_Target>
        </ttp:Exploit_Targets>
    </ttp:TTP>
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
    ```xml
    <coa:Course_Of_Action id="MISP:CourseOfAction-2497ac92-e751-4391-82c6-1b86e34d0294" timestamp="2020-11-21T12:46:33.153761+00:00" xsi:type='coa:CourseOfActionType'>
        <coa:Title>Automated Exfiltration Mitigation - T1020</coa:Title>
        <coa:Description>Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network</coa:Description>
    </coa:Course_Of_Action>
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
    ```xml
    <ttp:TTP id="MISP:TTP-b8eb28e4-48a6-40ae-951a-328714f75eda" timestamp="2020-11-21T12:46:33.154785+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>Malware (MISP Galaxy)</ttp:Title>
        <ttp:Behavior>
            <ttp:Malware>
                <ttp:Malware_Instance id="MISP:MalwareInstance-b8eb28e4-48a6-40ae-951a-328714f75eda">
                    <ttp:Name>BISCUIT</ttp:Name>
                    <ttp:Title>BISCUIT - S0017</ttp:Title>
                    <ttp:Description>BISCUIT is a backdoor that has been used by APT1 since as early as 2007.</ttp:Description>
                </ttp:Malware_Instance>
            </ttp:Malware>
        </ttp:Behavior>
    </ttp:TTP>
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
    ```xml
    <ta:Threat_Actor id="MISP:ThreatActor-11e17436-6ede-4733-8547-4ce0254ea19e" timestamp="2020-11-21T12:46:33.156154+00:00" xsi:type='ta:ThreatActorType'>
        <ta:Title>Cutting Kitten</ta:Title>
        <ta:Description>These convincing profiles form a self-referenced network of seemingly established LinkedIn users.</ta:Description>
        <ta:Intended_Effect timestamp="2020-11-21T12:46:33.156230+00:00">
            <stixCommon:Value>Denial of service</stixCommon:Value>
        </ta:Intended_Effect>
    </ta:Threat_Actor>
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
    ```xml
    <ttp:TTP id="MISP:TTP-bba595da-b73a-4354-aa6c-224d4de7cb4e" timestamp="2020-11-21T12:46:33.157528+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>Tool (MISP Galaxy)</ttp:Title>
        <ttp:Resources>
            <ttp:Tools>
                <ttp:Tool id="MISP:ToolInformation-bba595da-b73a-4354-aa6c-224d4de7cb4e">
                    <cyboxCommon:Name>cmd - S0106</cyboxCommon:Name>
                    <cyboxCommon:Description>cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.</cyboxCommon:Description>
                </ttp:Tool>
            </ttp:Tools>
        </ttp:Resources>
    </ttp:TTP>
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX1 mapping](misp_events_to_stix1.md)
- [Attributes export to STIX1 mapping](misp_attributes_to_stix1.md)
- [Objects export to STIX1 mapping](misp_objects_to_stix1.md)

([Go back to the main documentation](README.md))
