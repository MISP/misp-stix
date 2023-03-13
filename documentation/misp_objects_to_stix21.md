# MISP Objects to STIX1 mapping

MISP Objects are containers of single MISP attributes that are grouped together to highlight their meaning in a real use case scenario.
For instance, if you want to share a report with suspicious files, without object templates you would end up with a list of file names, hashes, and other attributes that are all mixed together, making the differentiation of each file difficult. In this case with the file object template, we simply group together all the attributes which belong to each file.
The list of currently supported templates is available [here](https://github.com/MISP/misp-objects).

As we can see in the [detailed Events mapping documentation](misp_events_to_stix21.md), objects within their event are exported in different STIX 2.1 objects embedded in a `STIX Bundle`. Those objects' references are also embedded within the report `object_refs` field.  
For the rest of this documentation, we will then, in order to keep the content clear enough and to skip the irrelevant part, consider the followings:
- MISP Objects are exported as Indicator or Observed Data object in most of the cases, depending on the `to_ids` flag:
  - If any `to_ids` flag is set in an object attribute, the object is exported as an Indicator.
  - If no `to_ids` flag is set, the object is exported as an Observed Data
  - Some objects are not exported either as Indicator nor as Observed Data.

### Current mapping

- Script object where state is "Malicious"
  - MISP
    ```json
    {
        "name": "script",
        "meta-category": "misc",
        "description": "Object describing a computer program written to be run in a special run-time environment.",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "language",
                "value": "Python"
            },
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
        ],
        "uuid": "ce12c406-cf09-457b-875a-41ab75d6dc4d"
    }
    ```
  - STIX
    - Malware
      ```json
      {
          "type": "malware",
          "spec_version": "2.1",
          "id": "malware--ce12c406-cf09-457b-875a-41ab75d6dc4d",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "infected.py",
          "description": "A script that infects command line shells",
          "is_family": false,
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "implementation_languages": [
              "Python"
          ],
          "labels": [
              "misp:name=\"script\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_script": "print('You are infected')",
          "x_misp_script_as_attachment": {
              "value": "infected.py",
              "data": "cHJpbnQoJ1lvdSBhcmUgaW5mZWN0ZWQnKQo="
          },
          "x_misp_state": "Malicious"
      }
      ```

- Script object where state is not "Malicious"
  - MISP
    ```json
    {
        "name": "script",
        "meta-category": "misc",
        "description": "Object describing a computer program written to be run in a special run-time environment.",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "language",
                "value": "Python"
            },
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
        ],
        "uuid": "9d14bdd1-5d32-4b4d-bd50-fd3a9d1c1c04"
    }
    ```
  - STIX
    - Tool
      ```json
      {
          "type": "tool",
          "spec_version": "2.1",
          "id": "tool--9d14bdd1-5d32-4b4d-bd50-fd3a9d1c1c04",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "hello.py",
          "description": "A peaceful script",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"script\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_language": "Python",
          "x_misp_script": "print('Hello World')",
          "x_misp_script_as_attachment": {
              "value": "hello.py",
              "data": "cHJpbnQoJ0hlbGxvIFdvcmxkJykK"
          },
          "x_misp_state": "Harmless"
      }
      ```

- android-app
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--02782ed5-b27f-4abc-8bae-efebe13a46dd",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[software:name = 'Facebook' AND software:x_misp_certificate = 'c3a94cdf5ad4d71fd60c16ba8801529c78e7398f' AND software:x_misp_domain = 'facebook.com']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"android-app\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--02782ed5-b27f-4abc-8bae-efebe13a46dd",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "software--02782ed5-b27f-4abc-8bae-efebe13a46dd"
              ],
              "labels": [
                  "misp:name=\"android-app\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "software",
              "spec_version": "2.1",
              "id": "software--02782ed5-b27f-4abc-8bae-efebe13a46dd",
              "name": "Facebook",
              "x_misp_certificate": "c3a94cdf5ad4d71fd60c16ba8801529c78e7398f",
              "x_misp_domain": "facebook.com"
          }
      ]
      ```

- annotation
  - MISP
    ```json
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
                "data": "OC44LjguOCBpcyB0aGUgR29[...]WRkcmVzc2VzIChJUHY0KS4K"
            }
        ],
        "ObjectReference": [
            {
                "referenced_uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "relationship_type": "annotates"
            }
        ]
    }
    ```
  - STIX
    - Note
      ```json
      {
          "type": "note",
          "spec_version": "2.1",
          "id": "note--eb6592bb-675c-48f3-9272-157141196b93",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "content": "Google public DNS",
          "object_refs": [
              "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
          ],
          "labels": [
              "misp:name=\"annotation\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_attachment": {
              "value": "annotation.attachment",
              "data": "OC44LjguOCBpcyB0aGUgR29[...]WRkcmVzc2VzIChJUHY0KS4K"
          },
          "x_misp_type": "Executive Summary"
      }
      ```

- asn
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[autonomous-system:number = '66642' AND autonomous-system:name = 'AS name' AND autonomous-system:x_misp_subnet_announced = '1.2.3.4' AND autonomous-system:x_misp_subnet_announced = '8.8.8.8']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"asn\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f"
              ],
              "labels": [
                  "misp:name=\"asn\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "autonomous-system",
              "spec_version": "2.1",
              "id": "autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f",
              "number": 66642,
              "name": "AS name",
              "x_misp_subnet_announced": [
                  "1.2.3.4",
                  "8.8.8.8"
              ]
          }
      ]
      ```

- attack-pattern
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Attack Pattern
      ```json
      {
          "type": "attack-pattern",
          "spec_version": "2.1",
          "id": "attack-pattern--7205da54-70de-4fa7-9b34-e14e63fe6787",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Buffer Overflow in Local Command-Line Utilities",
          "description": "This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root.",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "vulnerability"
              }
          ],
          "labels": [
              "misp:name=\"attack-pattern\"",
              "misp:meta-category=\"vulnerability\"",
              "misp:to_ids=\"False\""
          ],
          "external_references": [
              {
                  "source_name": "capec",
                  "external_id": "CAPEC-9"
              }
          ],
          "x_misp_prerequisites": "The target hosst exposes a command-line utility to the user. The command-line utility exposed by the target host has a buffer overflow vulnerability that can be exploited.",
          "x_misp_related_weakness": [
              "CWE-118",
              "CWE-120"
          ],
          "x_misp_solutions": "Carefully review the service\\'s implementation before making it available to users."
      }
      ```

- course-of-action
  - MISP
    ```json
    {
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
            }
        ]
    }
    ```
  - STIX
    - Course of Action
      ```json
      {
          "type": "course-of-action",
          "spec_version": "2.1",
          "id": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Block traffic to PIVY C2 Server (10.10.10.10)",
          "description": "Block communication between the PIVY agents and the C2 Server",
          "labels": [
              "misp:name=\"course-of-action\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_cost": "Low",
          "x_misp_efficacy": "High",
          "x_misp_impact": "Low",
          "x_misp_objective": "Block communication between the PIVY agents and the C2 Server",
          "x_misp_stage": "Response",
          "x_misp_type": "Perimeter Blocking"
      }
      ```

- cpe-asset
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--3f53a829-6307-4006-b7a2-ff53dace4159",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[software:cpe = 'cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*' AND software:languages = 'ENG' AND software:name = 'Word' AND software:vendor = 'Microsoft' AND software:version = '2002' AND software:x_misp_description = 'Microsoft Word is a word processing software developed by Microsoft.']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"cpe-asset\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--3f53a829-6307-4006-b7a2-ff53dace4159",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "software--3f53a829-6307-4006-b7a2-ff53dace4159"
              ],
              "labels": [
                  "misp:name=\"cpe-asset\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "software",
              "spec_version": "2.1",
              "id": "software--3f53a829-6307-4006-b7a2-ff53dace4159",
              "name": "Word",
              "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
              "languages": [
                  "ENG"
              ],
              "vendor": "Microsoft",
              "version": "2002",
              "x_misp_description": "Microsoft Word is a word processing software developed by Microsoft."
          }
      ]
      ```

- credential
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5b1f9378-46d4-494b-a4c1-044e0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:user_id = 'misp' AND user-account:credential = 'Password1234' AND user-account:x_misp_text = 'MISP default credentials' AND user-account:x_misp_type = 'password' AND user-account:x_misp_origin = 'malware-analysis' AND user-account:x_misp_format = 'clear-text' AND user-account:x_misp_notification = 'victim-notified']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"credential\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5b1f9378-46d4-494b-a4c1-044e0a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--5b1f9378-46d4-494b-a4c1-044e0a00020f"
              ],
              "labels": [
                  "misp:name=\"credential\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--5b1f9378-46d4-494b-a4c1-044e0a00020f",
              "user_id": "misp",
              "credential": "Password1234",
              "x_misp_format": "clear-text",
              "x_misp_notification": "victim-notified",
              "x_misp_origin": "malware-analysis",
              "x_misp_text": "MISP default credentials",
              "x_misp_type": "password"
          }
      ]
      ```

- domain-ip
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[domain-name:value = 'circl.lu' AND domain-name:x_misp_hostname = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14' AND domain-name:x_misp_port = '8443']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"domain-ip\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--dc624447-684a-488f-9e16-f78f717d8efd",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "domain-name--dc624447-684a-488f-9e16-f78f717d8efd",
                  "ipv4-addr--fcbaf339-615a-409c-915f-034420dc90ca"
              ],
              "labels": [
                  "misp:name=\"domain-ip\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "domain-name",
              "spec_version": "2.1",
              "id": "domain-name--dc624447-684a-488f-9e16-f78f717d8efd",
              "value": "circl.lu",
              "resolves_to_refs": [
                  "ipv4-addr--fcbaf339-615a-409c-915f-034420dc90ca"
              ],
              "x_misp_hostname": "circl.lu",
              "x_misp_port": "8443"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--fcbaf339-615a-409c-915f-034420dc90ca",
              "value": "149.13.33.14"
          }
      ]
      ```

- domain-ip with the perfect domain & ip matching
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac337df-e078-4e99-8b17-02550a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
                  "ipv4-addr--876133b5-b5fc-449c-ba9e-e467790da8eb",
                  "domain-name--a2e44443-a974-47b6-bb35-69d17b1cd243",
                  "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
              ],
              "labels": [
                  "misp:name=\"domain-ip\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "value": "149.13.33.14"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--876133b5-b5fc-449c-ba9e-e467790da8eb",
              "value": "185.194.93.14"
          },
          {
              "type": "domain-name",
              "spec_version": "2.1",
              "id": "domain-name--a2e44443-a974-47b6-bb35-69d17b1cd243",
              "value": "misp-project.org",
              "resolves_to_refs": [
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
                  "ipv4-addr--876133b5-b5fc-449c-ba9e-e467790da8eb"
              ]
          },
          {
              "type": "domain-name",
              "spec_version": "2.1",
              "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "circl.lu",
              "resolves_to_refs": [
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
                  "ipv4-addr--876133b5-b5fc-449c-ba9e-e467790da8eb"
              ]
          }
      ]
      ```

- email
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5e396622-2a54-4c8d-b61d-159da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:to_refs[0].value = 'jdoe@random.org' AND email-message:to_refs[0].display_name = 'John Doe' AND email-message:cc_refs[0].value = 'diana.prince@dc.us' AND email-message:cc_refs[0].display_name = 'Diana Prince' AND email-message:cc_refs[1].value = 'marie.curie@nobel.fr' AND email-message:cc_refs[1].display_name = 'Marie Curie' AND email-message:bcc_refs[0].value = 'jfk@gov.us' AND email-message:bcc_refs[0].display_name = 'John Fitzgerald Kennedy' AND email-message:from_ref.value = 'donald.duck@disney.com' AND email-message:from_ref.display_name = 'Donald Duck' AND email-message:message_id = '25' AND email-message:additional_header_fields.reply_to = 'reply-to@email.test' AND email-message:subject = 'Email test subject' AND email-message:additional_header_fields.x_mailer = 'x-mailer-test' AND email-message:body_multipart[0].body_raw_ref.name = 'attachment1.file' AND email-message:body_multipart[0].content_disposition = 'attachment' AND email-message:body_multipart[1].body_raw_ref.name = 'attachment2.file' AND email-message:body_multipart[1].content_disposition = 'attachment' AND email-message:x_misp_user_agent = 'Test user agent' AND email-message:x_misp_mime_boundary = 'Test mime boundary']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"email\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5e396622-2a54-4c8d-b61d-159da964451a",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "email-message--5e396622-2a54-4c8d-b61d-159da964451a",
                  "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
                  "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
                  "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
                  "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6",
                  "email-addr--3b940996-f99b-4bda-b065-69b8957f688c",
                  "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
                  "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a"
              ],
              "labels": [
                  "misp:name=\"email\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "email-message",
              "spec_version": "2.1",
              "id": "email-message--5e396622-2a54-4c8d-b61d-159da964451a",
              "is_multipart": true,
              "from_ref": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
              "to_refs": [
                  "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46"
              ],
              "cc_refs": [
                  "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
                  "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6"
              ],
              "bcc_refs": [
                  "email-addr--3b940996-f99b-4bda-b065-69b8957f688c"
              ],
              "message_id": "25",
              "subject": "Email test subject",
              "additional_header_fields": {
                  "Reply-To": "reply-to@email.test",
                  "X-Mailer": "x-mailer-test"
              },
              "body_multipart": [
                  {
                      "body_raw_ref": "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
                      "content_disposition": "attachment; filename='attachment1.file'"
                  },
                  {
                      "body_raw_ref": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
                      "content_disposition": "attachment; filename='attachment2.file'"
                  }
              ],
              "x_misp_mime_boundary": "Test mime boundary",
              "x_misp_user_agent": "Test user agent"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
              "value": "donald.duck@disney.com",
              "display_name": "Donald Duck"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
              "value": "jdoe@random.org",
              "display_name": "John Doe"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
              "value": "diana.prince@dc.us",
              "display_name": "Diana Prince"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6",
              "value": "marie.curie@nobel.fr",
              "display_name": "Marie Curie"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--3b940996-f99b-4bda-b065-69b8957f688c",
              "value": "jfk@gov.us",
              "display_name": "John Fitzgerald Kennedy"
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
              "name": "attachment1.file"
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
              "name": "attachment2.file"
          }
      ]
      ```

- email with display names
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:to_refs[0].value = 'jdoe@random.org' AND email-message:to_refs[0].display_name = 'John Doe' AND email-message:cc_refs[0].value = 'diana.prince@dc.us' AND email-message:cc_refs[1].display_name = 'Marie Curie' AND email-message:bcc_refs[0].value = 'jfk@gov.us' AND email-message:bcc_refs[0].display_name = 'John Fitzgerald Kennedy' AND email-message:from_ref.value = 'donald.duck@disney.com' AND email-message:from_ref.display_name = 'Donald Duck']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"email\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "grouping",
              "spec_version": "2.1",
              "id": "grouping--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "name": "MISP-STIX-Converter test event",
              "context": "suspicious-activity",
              "object_refs": [
                  "observed-data--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
                  "email-message--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
                  "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
                  "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
                  "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
                  "email-addr--3b940996-f99b-4bda-b065-69b8957f688c"
              ],
              "labels": [
                  "Threat-Report",
                  "misp:tool=\"MISP-STIX-Converter\""
              ]
          },
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "email-message--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
                  "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
                  "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
                  "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
                  "email-addr--3b940996-f99b-4bda-b065-69b8957f688c"
              ],
              "labels": [
                  "misp:name=\"email\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "email-message",
              "spec_version": "2.1",
              "id": "email-message--f8fa460c-9e7a-4870-bf46-fed2da3a64f8",
              "is_multipart": false,
              "from_ref": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
              "to_refs": [
                  "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46"
              ],
              "cc_refs": [
                  "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6"
              ],
              "bcc_refs": [
                  "email-addr--3b940996-f99b-4bda-b065-69b8957f688c"
              ],
              "x_misp_cc_display_name": "Marie Curie"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
              "value": "donald.duck@disney.com",
              "display_name": "Donald Duck"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
              "value": "jdoe@random.org",
              "display_name": "John Doe"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
              "value": "diana.prince@dc.us"
          },
          {
              "type": "email-addr",
              "spec_version": "2.1",
              "id": "email-addr--3b940996-f99b-4bda-b065-69b8957f688c",
              "value": "jfk@gov.us",
              "display_name": "John Fitzgerald Kennedy"
          }
      ]
      ```

- employee
  - MISP
    ```json
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
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--685a38e1-3ca1-40ef-874d-3a04b9fb3af6",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "John Doe",
          "description": "John Doe is known",
          "roles": [
              "Supervisor"
          ],
          "identity_class": "individual",
          "contact_information": "email-address: jdoe@email.com",
          "labels": [
              "misp:name=\"employee\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ]
      }
      ```

- facebook-account
  - MISP
    ```json
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
                "value": "octocat.png",
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'facebook' AND user-account:user_id = '1392781243' AND user-account:account_login = 'octocat' AND user-account:x_misp_link = 'https://facebook.com/octocat' AND user-account:x_misp_user_avatar.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_user_avatar.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"facebook-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--7d8ac653-b65c-42a6-8420-ddc71d65f50d"
              ],
              "labels": [
                  "misp:name=\"facebook-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
              "user_id": "1392781243",
              "account_login": "octocat",
              "account_type": "facebook",
              "x_misp_link": "https://facebook.com/octocat",
              "x_misp_user_avatar": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              }
          }
      ]
      ```

- file
  - MISP
    ```json
    {
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
                "data": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA=="
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86' AND file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b' AND file:name = 'oui' AND file:name_enc = 'UTF-8' AND file:size = '35' AND file:ctime = '2021-10-25T16:22:00Z' AND file:mtime = '2022-10-25T16:22:00Z' AND file:parent_directory_ref.path = '/var/www/MISP/app/files/scripts/tmp' AND (file:content_ref.payload_bin = 'UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==' AND file:content_ref.x_misp_filename = 'oui' AND file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:content_ref.mime_type = 'application/zip' AND file:content_ref.encryption_algorithm = 'mime-type-indicated' AND file:content_ref.decryption_key = 'infected') AND (file:content_ref.payload_bin = 'Tm9uLW1hbGljaW91cyBmaWxlCg==' AND file:content_ref.x_misp_filename = 'non')]",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"file\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
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
              "labels": [
                  "misp:name=\"file\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
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
              "ctime": "2021-10-25T16:22:00Z",
              "mtime": "2022-10-25T16:22:00Z",
              "parent_directory_ref": "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
              "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "x_misp_attachment": {
                  "value": "non",
                  "data": "Tm9uLW1hbGljaW91cyBmaWxlCg=="
              }
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
              "payload_bin": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==",
              "hashes": {
                  "MD5": "8764605c6f388c89096b534d33565802"
              },
              "encryption_algorithm": "mime-type-indicated",
              "decryption_key": "infected",
              "x_misp_filename": "oui"
          }
      ]
      ```

- file with references to pe & pe-section(s)
  - MISP
    ```json
    [
        {
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
                    "value": "8a2a5fc2ce56b3b04d58539a95390600"
                },
                {
                    "type": "sha1",
                    "object_relation": "sha1",
                    "value": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf"
                },
                {
                    "type": "sha256",
                    "object_relation": "sha256",
                    "value": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b"
                },
                {
                    "type": "sha512",
                    "object_relation": "sha512",
                    "value": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f"
                },
                {
                    "type": "ssdeep",
                    "object_relation": "ssdeep",
                    "value": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                }
            ]
        }
    ]
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5ac47782-e1b8-40b6-96b4-02510a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND file:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND file:hashes.SHA256 = '3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8' AND file:name = 'oui' AND file:size = '1234' AND file:x_misp_entropy = '1.234' AND file:extensions.'windows-pebinary-ext'.imphash = '23ea835ab4b9017c74dfb023d2301c99' AND file:extensions.'windows-pebinary-ext'.number_of_sections = '8' AND file:extensions.'windows-pebinary-ext'.pe_type = 'exe' AND file:extensions.'windows-pebinary-ext'.optional_header.address_of_entry_point = '5369222868' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2019-03-16T12:31:22Z' AND file:extensions.'windows-pebinary-ext'.x_misp_original_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_internal_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_file_description = 'SSH, Telnet and Rlogin client' AND file:extensions.'windows-pebinary-ext'.x_misp_file_version = 'Release 0.71 (with embedded help)' AND file:extensions.'windows-pebinary-ext'.x_misp_lang_id = '080904B0' AND file:extensions.'windows-pebinary-ext'.x_misp_product_name = 'PuTTy suite' AND file:extensions.'windows-pebinary-ext'.x_misp_product_version = 'Release 0.71' AND file:extensions.'windows-pebinary-ext'.x_misp_company_name = 'Simoe Tatham' AND file:extensions.'windows-pebinary-ext'.x_misp_legal_copyright = 'Copyright \u00a9 1997-2019 Simon Tatham.' AND file:extensions.'windows-pebinary-ext'.x_misp_impfuzzy = '192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt' AND file:extensions.'windows-pebinary-ext'.sections[0].entropy = '7.836462238824369' AND file:extensions.'windows-pebinary-ext'.sections[0].name = '.rsrc' AND file:extensions.'windows-pebinary-ext'.sections[0].size = '305152' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.MD5 = '8a2a5fc2ce56b3b04d58539a95390600' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA1 = '0aeb9def096e9f73e9460afe6f8783a32c7eabdf' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA256 = 'c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA512 = '98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SSDEEP = '6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"file\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac47782-e1b8-40b6-96b4-02510a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "file--5ac47782-e1b8-40b6-96b4-02510a00020f"
              ],
              "labels": [
                  "misp:name=\"file\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--5ac47782-e1b8-40b6-96b4-02510a00020f",
              "hashes": {
                  "MD5": "b2a5abfeef9e36964281a31e17b57c97",
                  "SHA-1": "5898fc860300e228dcd54c0b1045b5fa0dcda502",
                  "SHA-256": "3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8"
              },
              "size": 1234,
              "name": "oui",
              "extensions": {
                  "windows-pebinary-ext": {
                      "pe_type": "exe",
                      "imphash": "23ea835ab4b9017c74dfb023d2301c99",
                      "number_of_sections": 8,
                      "optional_header": {
                          "address_of_entry_point": 5369222868
                      },
                      "sections": [
                          {
                              "name": ".rsrc",
                              "size": 305152,
                              "entropy": 7.836462238824369,
                              "hashes": {
                                  "MD5": "8a2a5fc2ce56b3b04d58539a95390600",
                                  "SHA-1": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf",
                                  "SHA-256": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b",
                                  "SHA-512": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f",
                                  "SSDEEP": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                              }
                          }
                      ],
                      "x_misp_company_name": "Simoe Tatham",
                      "x_misp_compilation_timestamp": "2019-03-16T12:31:22Z",
                      "x_misp_file_description": "SSH, Telnet and Rlogin client",
                      "x_misp_file_version": "Release 0.71 (with embedded help)",
                      "x_misp_impfuzzy": "192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt",
                      "x_misp_internal_filename": "PuTTy",
                      "x_misp_lang_id": "080904B0",
                      "x_misp_legal_copyright": "Copyright \u00a9 1997-2019 Simon Tatham.",
                      "x_misp_original_filename": "PuTTy",
                      "x_misp_product_name": "PuTTy suite",
                      "x_misp_product_version": "Release 0.71"
                  }
              },
              "x_misp_entropy": "1.234"
          }
      ]
      ```

- geolocation
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Location
      ```json
      {
          "type": "location",
          "spec_version": "2.1",
          "id": "location--6a10dac8-71ac-4d9b-8269-1e9c73ea4d8f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "latitude": 39.108889,
          "longitude": -76.771389,
          "precision": 1000.0,
          "region": "northern-america",
          "country": "US",
          "city": "Fort Meade",
          "street_address": "9800 Savage Rd. Suite 6272",
          "postal_code": "MD 20755",
          "labels": [
              "misp:name=\"geolocation\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_altitude": "55",
          "x_misp_country": "USA"
      }
      ```

- github-user
  - MISP
    ```json
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
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5177abbd-c437-4acb-9173-eee371ad24da",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'github' AND user-account:user_id = '1' AND user-account:display_name = 'Octo Cat' AND user-account:account_login = 'octocat' AND user-account:x_misp_organisation = 'GitHub' AND user-account:x_misp_profile_image.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_profile_image.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"github-user\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5177abbd-c437-4acb-9173-eee371ad24da",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--5177abbd-c437-4acb-9173-eee371ad24da"
              ],
              "labels": [
                  "misp:name=\"github-user\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--5177abbd-c437-4acb-9173-eee371ad24da",
              "user_id": "1",
              "account_login": "octocat",
              "account_type": "github",
              "display_name": "Octo Cat",
              "x_misp_organisation": "GitHub",
              "x_misp_profile_image": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              }
          }
      ]
      ```

- gitlab-user
  - MISP
    ```json
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
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'gitlab' AND user-account:user_id = '1234567890' AND user-account:display_name = 'John Doe' AND user-account:account_login = 'j0hnd0e']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"gitlab-user\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b"
              ],
              "labels": [
                  "misp:name=\"gitlab-user\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
              "user_id": "1234567890",
              "account_login": "j0hnd0e",
              "account_type": "gitlab",
              "display_name": "John Doe"
          }
      ]
      ```

- http-request
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--cfdb71ed-889f-4646-a388-43d936e1e3b9",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "network-traffic--cfdb71ed-889f-4646-a388-43d936e1e3b9",
                  "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                  "ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7",
                  "domain-name--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
              ],
              "labels": [
                  "misp:name=\"http-request\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "network-traffic",
              "spec_version": "2.1",
              "id": "network-traffic--cfdb71ed-889f-4646-a388-43d936e1e3b9",
              "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "dst_ref": "ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7",
              "protocols": [
                  "tcp",
                  "http"
              ],
              "extensions": {
                  "http-request-ext": {
                      "request_method": "POST",
                      "request_value": "/projects/internships/",
                      "request_header": {
                          "Content-Type": "JSON",
                          "User-Agent": "Mozilla Firefox"
                      }
                  }
              },
              "x_misp_url": "http://circl.lu/projects/internships/"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "8.8.8.8"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7",
              "value": "149.13.33.14"
          },
          {
              "type": "domain-name",
              "spec_version": "2.1",
              "id": "domain-name--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
              "value": "circl.lu",
              "resolves_to_refs": [
                  "ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7"
              ]
          }
      ]
      ```
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--cfdb71ed-889f-4646-a388-43d936e1e3b9",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '8.8.8.8') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '149.13.33.14') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:extensions.'http-request-ext'.request_method = 'POST' AND network-traffic:extensions.'http-request-ext'.request_value = '/projects/internships/' AND network-traffic:extensions.'http-request-ext'.request_value = 'http://circl.lu/projects/internships/' AND network-traffic:extensions.'http-request-ext'.request_header.'Content-Type' = 'JSON' AND network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'Mozilla Firefox']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"http-request\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```

- identity
  - MISP
    ```json
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
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--a54e32af-5569-4949-b1fe-ad75054cde45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "John Doe",
          "description": "Unknown person",
          "roles": [
              "Placeholder name"
          ],
          "identity_class": "individual",
          "contact_information": "email-address: jdoe@email.com / phone-number: 0123456789",
          "labels": [
              "misp:name=\"identity\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ]
      }
      ```

- image
  - MISP
    ```json
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
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]gEefQAAAABJRU5ErkJggg=="
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--939b2f03-c487-4f62-a90e-cab7acfee294",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:name = 'STIX.png' AND file:content_ref.payload_bin = 'iVBORw0KGgoAAAANSUhEUgA[...]gEefQAAAABJRU5ErkJggg==' AND file:content_ref.mime_type = 'image/png' AND file:content_ref.x_misp_filename = 'STIX.png' AND file:content_ref.url = 'https://oasis-open.github.io/cti-documentation/img/STIX.png' AND file:x_misp_image_text = 'STIX']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"image\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--939b2f03-c487-4f62-a90e-cab7acfee294",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "file--939b2f03-c487-4f62-a90e-cab7acfee294",
                  "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
              ],
              "labels": [
                  "misp:name=\"image\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--939b2f03-c487-4f62-a90e-cab7acfee294",
              "name": "STIX.png",
              "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "x_misp_image_text": "STIX"
          },
          {
              "type": "artifact",
              "spec_version": "2.1",
              "id": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "mime_type": "image/png",
              "payload_bin": "iVBORw0KGgoAAAANSUhEUgA[...]gEefQAAAABJRU5ErkJggg==",
              "x_misp_filename": "STIX.png",
              "x_misp_url": "https://oasis-open.github.io/cti-documentation/img/STIX.png"
          }
      ]
      ```

- ip-port
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '149.13.33.14') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '443' AND network-traffic:start = '2020-10-25T16:22:00Z']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"ip-port\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac47edc-31e4-4402-a7b6-040d0a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "network-traffic--5ac47edc-31e4-4402-a7b6-040d0a00020f",
                  "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
              ],
              "labels": [
                  "misp:name=\"ip-port\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "network-traffic",
              "spec_version": "2.1",
              "id": "network-traffic--5ac47edc-31e4-4402-a7b6-040d0a00020f",
              "start": "2020-10-25T16:22:00Z",
              "dst_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "dst_port": 443,
              "protocols": [
                  "ipv4"
              ],
              "x_misp_domain": "circl.lu"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "149.13.33.14"
          }
      ]
      ```

- legal-entity
  - MISP
    ```json
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
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]DAbmag+AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--0d55ba1f-c3ff-4b91-8a09-8713576e178b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Umbrella Corporation",
          "description": "The Umbrella Corporation is an international pharmaceutical company.",
          "identity_class": "organization",
          "sectors": [
              "Pharmaceutical"
          ],
          "contact_information": "phone-number: 1234567890 / website: https://umbrella.org",
          "labels": [
              "misp:name=\"legal-entity\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_logo": {
              "value": "umbrella_logo",
              "data": "iVBORw0KGgoAAAANSUhEUgA[...]DAbmag+AAAAAElFTkSuQmCC"
          },
          "x_misp_registration_number": "11223344556677889900"
      }
      ```

- lnk
  - MISP
    ```json
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
                "data": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA=="
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:atime = '2021-01-01T00:00:00Z' AND file:ctime = '2017-10-01T08:00:00Z' AND file:mtime = '2020-10-25T16:22:00Z' AND file:name = 'oui' AND file:parent_directory_ref.path = '/var/www/MISP/app/files/scripts/tmp' AND file:hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86' AND file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b' AND (file:content_ref.payload_bin = 'UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==' AND file:content_ref.x_misp_filename = 'oui' AND file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:content_ref.mime_type = 'application/zip' AND file:content_ref.encryption_algorithm = 'mime-type-indicated' AND file:content_ref.decryption_key = 'infected') AND file:size = '35']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"lnk\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "file--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
                  "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                  "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
              ],
              "labels": [
                  "misp:name=\"lnk\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
              "hashes": {
                  "MD5": "8764605c6f388c89096b534d33565802",
                  "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                  "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
              },
              "size": 35,
              "name": "oui",
              "ctime": "2017-10-01T08:00:00Z",
              "mtime": "2020-10-25T16:22:00Z",
              "atime": "2021-01-01T00:00:00Z",
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
              "payload_bin": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==",
              "hashes": {
                  "MD5": "8764605c6f388c89096b534d33565802"
              },
              "encryption_algorithm": "mime-type-indicated",
              "decryption_key": "infected",
              "x_misp_filename": "oui"
          }
      ]
      ```

- mutex
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--b0f55591-6a63-4fbd-a169-064e64738d95",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[mutex:name = 'MutexTest' AND mutex:x_misp_description = 'Test mutex on unix' AND mutex:x_misp_operating_system = 'Unix']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"mutex\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--b0f55591-6a63-4fbd-a169-064e64738d95",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "mutex--b0f55591-6a63-4fbd-a169-064e64738d95"
              ],
              "labels": [
                  "misp:name=\"mutex\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "mutex",
              "spec_version": "2.1",
              "id": "mutex--b0f55591-6a63-4fbd-a169-064e64738d95",
              "name": "MutexTest",
              "x_misp_description": "Test mutex on unix",
              "x_misp_operating_system": "Unix"
          }
      ]
      ```

- netflow
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4' AND network-traffic:src_ref.belongs_to_refs[0].number = '1234') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8' AND network-traffic:dst_ref.belongs_to_refs[0].number = '5678') AND network-traffic:protocols[0] = 'ip' AND network-traffic:src_port = '80' AND network-traffic:dst_port = '8080' AND network-traffic:start = '2020-10-25T16:22:00Z' AND network-traffic:extensions.'tcp-ext'.src_flags_hex = '00000002']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"netflow\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "network-traffic--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
                  "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                  "autonomous-system--53a12da9-4b66-4809-b0b4-e9de3172e7a0",
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
                  "autonomous-system--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
              ],
              "labels": [
                  "misp:name=\"netflow\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "network-traffic",
              "spec_version": "2.1",
              "id": "network-traffic--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
              "start": "2020-10-25T16:22:00Z",
              "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "src_port": 80,
              "dst_port": 8080,
              "protocols": [
                  "ip",
                  "tcp"
              ],
              "extensions": {
                  "tcp-ext": {
                      "src_flags_hex": "00000002"
                  }
              }
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "1.2.3.4",
              "belongs_to_refs": [
                  "autonomous-system--53a12da9-4b66-4809-b0b4-e9de3172e7a0"
              ]
          },
          {
              "type": "autonomous-system",
              "spec_version": "2.1",
              "id": "autonomous-system--53a12da9-4b66-4809-b0b4-e9de3172e7a0",
              "number": 1234
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "value": "5.6.7.8",
              "belongs_to_refs": [
                  "autonomous-system--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
              ]
          },
          {
              "type": "autonomous-system",
              "spec_version": "2.1",
              "id": "autonomous-system--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
              "number": 5678
          }
      ]
      ```

- network-connection
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5afacc53-c0b0-4825-a6ee-03c80a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '8080' AND network-traffic:src_port = '8080' AND network-traffic:protocols[0] = 'ip' AND network-traffic:protocols[1] = 'tcp' AND network-traffic:protocols[2] = 'http']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"network-connection\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5afacc53-c0b0-4825-a6ee-03c80a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "network-traffic--5afacc53-c0b0-4825-a6ee-03c80a00020f",
                  "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b"
              ],
              "labels": [
                  "misp:name=\"network-connection\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "network-traffic",
              "spec_version": "2.1",
              "id": "network-traffic--5afacc53-c0b0-4825-a6ee-03c80a00020f",
              "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "src_port": 8080,
              "dst_port": 8080,
              "protocols": [
                  "ip",
                  "tcp",
                  "http"
              ],
              "x_misp_hostname_dst": "circl.lu"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "1.2.3.4"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "value": "5.6.7.8"
          }
      ]
      ```

- network-socket
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '8080' AND network-traffic:src_port = '8080' AND network-traffic:protocols[0] = 'tcp' AND network-traffic:extensions.'socket-ext'.address_family = 'AF_INET' AND network-traffic:extensions.'socket-ext'.socket_type = 'SOCK_RAW' AND network-traffic:extensions.'socket-ext'.is_listening = true AND network-traffic:x_misp_domain_family = 'PF_INET']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"network-socket\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5afb3223-0988-4ef1-a920-02070a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "network-traffic--5afb3223-0988-4ef1-a920-02070a00020f",
                  "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                  "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b"
              ],
              "labels": [
                  "misp:name=\"network-socket\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "network-traffic",
              "spec_version": "2.1",
              "id": "network-traffic--5afb3223-0988-4ef1-a920-02070a00020f",
              "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "src_port": 8080,
              "dst_port": 8080,
              "protocols": [
                  "tcp"
              ],
              "extensions": {
                  "socket-ext": {
                      "address_family": "AF_INET",
                      "is_listening": true,
                      "socket_type": "SOCK_RAW"
                  }
              },
              "x_misp_domain_family": "PF_INET",
              "x_misp_hostname_dst": "circl.lu"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
              "value": "1.2.3.4"
          },
          {
              "type": "ipv4-addr",
              "spec_version": "2.1",
              "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
              "value": "5.6.7.8"
          }
      ]
      ```

- news-agency
  - MISP
    ```json
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
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]OkjUAAAAABJRU5ErkJggg=="
            }
        ]
    }
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--d17e31ce-5a7a-4713-bdff-49d89548c259",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Agence France-Presse",
          "identity_class": "organization",
          "contact_information": "address: 13 place de la Bourse, 75002 Paris; Southern Railway Building, 1500 K Street, NW, Suite 600 / e-mail: contact@afp.fr; contact@afp.us / phone-number: (33)0140414646; (1)2024140600 / link: https://www.afp.com/",
          "labels": [
              "misp:name=\"news-agency\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_attachment": {
              "value": "AFP_logo.png",
              "data": "iVBORw0KGgoAAAANSUhEUgA[...]OkjUAAAAABJRU5ErkJggg=="
          }
      }
      ```

- organization
  - MISP
    ```json
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
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--fe85995c-189d-4c20-9d0e-dfc03e72000b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Computer Incident Response Center of Luxembourg",
          "description": "The Computer Incident Response Center Luxembourg (CIRCL) is a government-driven initiative designed to gather, review, report and respond to computer security threats and incidents.",
          "roles": [
              "national CERT"
          ],
          "identity_class": "organization",
          "contact_information": "address: 16, bd d'Avranches, L-1160 Luxembourg / e-mail: info@circl.lu / phone-number: (+352) 247 88444",
          "labels": [
              "misp:name=\"organization\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_alias": "CIRCL"
      }
      ```

- parler-account
  - MISP
    ```json
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
                "value": false
            },
            {
                "type": "attachment",
                "object_relation": "profile-photo",
                "value": "octocat.png",
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'parler' AND user-account:user_id = '42' AND user-account:account_login = 'ParlerOctocat' AND user-account:x_misp_human = 'False' AND user-account:x_misp_profile_photo.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_profile_photo.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"parler-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--7b0698a0-209a-4da0-a5c5-cfc4734f3af2"
              ],
              "labels": [
                  "misp:name=\"parler-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
              "user_id": "42",
              "account_login": "ParlerOctocat",
              "account_type": "parler",
              "x_misp_human": false,
              "x_misp_profile_photo": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              }
          }
      ]
      ```

- pe & pe-sections
  - MISP
    ```json
    [
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
                    "value": "8a2a5fc2ce56b3b04d58539a95390600"
                },
                {
                    "type": "sha1",
                    "object_relation": "sha1",
                    "value": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf"
                },
                {
                    "type": "sha256",
                    "object_relation": "sha256",
                    "value": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b"
                },
                {
                    "type": "sha512",
                    "object_relation": "sha512",
                    "value": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f"
                },
                {
                    "type": "ssdeep",
                    "object_relation": "ssdeep",
                    "value": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                }
            ]
        }
    ]
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--2183705f-e8d6-4c08-a820-5b56a1303bb1",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:extensions.'windows-pebinary-ext'.imphash = '23ea835ab4b9017c74dfb023d2301c99' AND file:extensions.'windows-pebinary-ext'.number_of_sections = '8' AND file:extensions.'windows-pebinary-ext'.pe_type = 'exe' AND file:extensions.'windows-pebinary-ext'.optional_header.address_of_entry_point = '5369222868' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2019-03-16T12:31:22Z' AND file:extensions.'windows-pebinary-ext'.x_misp_original_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_internal_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_file_description = 'SSH, Telnet and Rlogin client' AND file:extensions.'windows-pebinary-ext'.x_misp_file_version = 'Release 0.71 (with embedded help)' AND file:extensions.'windows-pebinary-ext'.x_misp_lang_id = '080904B0' AND file:extensions.'windows-pebinary-ext'.x_misp_product_name = 'PuTTy suite' AND file:extensions.'windows-pebinary-ext'.x_misp_product_version = 'Release 0.71' AND file:extensions.'windows-pebinary-ext'.x_misp_company_name = 'Simoe Tatham' AND file:extensions.'windows-pebinary-ext'.x_misp_legal_copyright = 'Copyright \u00a9 1997-2019 Simon Tatham.' AND file:extensions.'windows-pebinary-ext'.x_misp_impfuzzy = '192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt' AND file:extensions.'windows-pebinary-ext'.sections[0].entropy = '7.836462238824369' AND file:extensions.'windows-pebinary-ext'.sections[0].name = '.rsrc' AND file:extensions.'windows-pebinary-ext'.sections[0].size = '305152' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.MD5 = '8a2a5fc2ce56b3b04d58539a95390600' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA1 = '0aeb9def096e9f73e9460afe6f8783a32c7eabdf' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA256 = 'c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA512 = '98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SSDEEP = '6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"pe\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--2183705f-e8d6-4c08-a820-5b56a1303bb1",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "file--ac549e74-924a-5164-a14d-8bfe0a5ba40f"
              ],
              "labels": [
                  "misp:name=\"pe\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--ac549e74-924a-5164-a14d-8bfe0a5ba40f",
              "name": "PuTTy",
              "extensions": {
                  "windows-pebinary-ext": {
                      "pe_type": "exe",
                      "imphash": "23ea835ab4b9017c74dfb023d2301c99",
                      "number_of_sections": 8,
                      "optional_header": {
                          "address_of_entry_point": 5369222868
                      },
                      "sections": [
                          {
                              "name": ".rsrc",
                              "size": 305152,
                              "entropy": 7.836462238824369,
                              "hashes": {
                                  "MD5": "8a2a5fc2ce56b3b04d58539a95390600",
                                  "SHA-1": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf",
                                  "SHA-256": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b",
                                  "SHA-512": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f",
                                  "SSDEEP": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                              }
                          }
                      ],
                      "x_misp_company_name": "Simoe Tatham",
                      "x_misp_compilation_timestamp": "2019-03-16T12:31:22Z",
                      "x_misp_file_description": "SSH, Telnet and Rlogin client",
                      "x_misp_file_version": "Release 0.71 (with embedded help)",
                      "x_misp_impfuzzy": "192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt",
                      "x_misp_internal_filename": "PuTTy",
                      "x_misp_lang_id": "080904B0",
                      "x_misp_legal_copyright": "Copyright \u00a9 1997-2019 Simon Tatham.",
                      "x_misp_original_filename": "PuTTy",
                      "x_misp_product_name": "PuTTy suite",
                      "x_misp_product_version": "Release 0.71"
                  }
              }
          }
      ]
      ```

- person
  - MISP
    ```json
    {
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
    ```
  - STIX
    - Identity
      ```json
      {
          "type": "identity",
          "spec_version": "2.1",
          "id": "identity--868037d5-d804-4f1d-8016-f296361f9c68",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "John Smith",
          "roles": [
              "Guru"
          ],
          "identity_class": "individual",
          "contact_information": "phone-number: 0123456789",
          "labels": [
              "misp:name=\"person\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"False\""
          ],
          "x_misp_nationality": "USA",
          "x_misp_passport_number": "ABA9875413"
      }
      ```

- process
  - MISP
    ```json
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
            },
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
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5e39776a-b284-40b3-8079-22fea964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[process:is_hidden = 'True' AND process:pid = '2510' AND process:image_ref.name = 'test_process.exe' AND process:parent_ref.command_line = 'grep -nrG iglocska /home/viktor/friends.txt' AND process:parent_ref.image_ref.name = 'parent_process.exe' AND process:parent_ref.pid = '2107' AND process:parent_ref.x_misp_process_name = 'Friends_From_H' AND process:child_refs[0].pid = '1401' AND process:x_misp_name = 'TestProcess' AND process:x_misp_port = '1234']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"process\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5e39776a-b284-40b3-8079-22fea964451a",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "process--5e39776a-b284-40b3-8079-22fea964451a",
                  "file--d01ef2c6-3154-4f8a-a3dc-9de1f34dd5d0",
                  "process--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                  "process--518b4bcb-a86b-4783-9457-391d548b605b",
                  "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
              ],
              "labels": [
                  "misp:name=\"process\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "process",
              "spec_version": "2.1",
              "id": "process--5e39776a-b284-40b3-8079-22fea964451a",
              "is_hidden": true,
              "pid": 2510,
              "image_ref": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
              "parent_ref": "process--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
              "child_refs": [
                  "process--518b4bcb-a86b-4783-9457-391d548b605b"
              ],
              "x_misp_name": "TestProcess",
              "x_misp_port": "1234"
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--d01ef2c6-3154-4f8a-a3dc-9de1f34dd5d0",
              "name": "parent_process.exe"
          },
          {
              "type": "process",
              "spec_version": "2.1",
              "id": "process--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
              "pid": 2107,
              "command_line": "grep -nrG iglocska /home/viktor/friends.txt",
              "image_ref": "file--d01ef2c6-3154-4f8a-a3dc-9de1f34dd5d0",
              "x_misp_process_name": "Friends_From_H"
          },
          {
              "type": "process",
              "spec_version": "2.1",
              "id": "process--518b4bcb-a86b-4783-9457-391d548b605b",
              "pid": 1401
          },
          {
              "type": "file",
              "spec_version": "2.1",
              "id": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
              "name": "test_process.exe"
          }
      ]
      ```

- reddit-account
  - MISP
    ```json
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
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'reddit' AND user-account:user_id = '666' AND user-account:account_login = 'RedditOctocat' AND user-account:x_misp_description = 'Reddit account of the OctoCat' AND user-account:x_misp_account_avatar.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_account_avatar.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"reddit-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--43d3eff0-fabc-4663-9493-fad3a1eed0d5"
              ],
              "labels": [
                  "misp:name=\"reddit-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
              "user_id": "666",
              "account_login": "RedditOctocat",
              "account_type": "reddit",
              "x_misp_account_avatar": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              },
              "x_misp_description": "Reddit account of the OctoCat"
          }
      ]
      ```

- registry-key
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5ac3379c-3e74-44ba-9160-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[windows-registry-key:key = 'hkey_local_machine\\\\system\\\\bar\\\\foo' AND windows-registry-key:modified_time = '2020-10-25T16:22:00Z' AND windows-registry-key:values[0].data = '\\\\%DATA\\\\%\\\\qwertyuiop' AND windows-registry-key:values[0].data_type = 'REG_SZ' AND windows-registry-key:values[0].name = 'RegistryName' AND windows-registry-key:x_misp_hive = 'hklm']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:name=\"registry-key\"",
              "misp:meta-category=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac3379c-3e74-44ba-9160-04120a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "windows-registry-key--5ac3379c-3e74-44ba-9160-04120a00020f"
              ],
              "labels": [
                  "misp:name=\"registry-key\"",
                  "misp:meta-category=\"file\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "windows-registry-key",
              "spec_version": "2.1",
              "id": "windows-registry-key--5ac3379c-3e74-44ba-9160-04120a00020f",
              "key": "hkey_local_machine\\system\\bar\\foo",
              "values": [
                  {
                      "name": "RegistryName",
                      "data": "%DATA%\\qwertyuiop",
                      "data_type": "REG_SZ"
                  }
              ],
              "modified_time": "2020-10-25T16:22:00Z",
              "x_misp_hive": "hklm"
          }
      ]
      ```

- sigma
  - MISP
    ```json
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
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--c8c418e3-b61c-4d40-a1fc-b10cec6585d7",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Ps.exe",
          "description": "Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A",
          "pattern": "title: Ps.exe Renamed SysInternals Tool description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A report reference: https://www.us-cert.gov/ncas/alerts/TA17-293A author: Florian Roth date: 2017/10/22 logsource: product: windows service: sysmon detection: selection: EventID: 1 CommandLine: \\'ps.exe -accepteula\\' condition: selection falsepositives: - Renamed SysInternals tool level: high",
          "pattern_type": "sigma",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"sigma\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ],
          "external_references": [
              {
                  "source_name": "url",
                  "url": "https://www.us-cert.gov/ncas/alerts/TA17-293A"
              }
          ],
          "x_misp_context": "disk"
      }
      ```

- suricata
  - MISP
    ```json
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
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--efc15547-4fe9-4188-aa71-b688e1bfa59c",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "To rule them all",
          "pattern": "alert http any 443 -> 8.8.8.8 any",
          "pattern_type": "snort",
          "pattern_version": "3.1.6",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"suricata\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ],
          "external_references": [
              {
                  "source_name": "url",
                  "url": "https://suricata.readthedocs.io/en/suricata-6.0.4/index.html"
              }
          ]
      }
      ```

- telegram-account
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--7ecc4537-89cd-4f17-8027-6e0f70710c53",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'telegram' AND user-account:user_id = '1234567890' AND user-account:account_login = 'T3l3gr4mUs3r' AND user-account:x_misp_phone = '0112233445' AND user-account:x_misp_phone = '0556677889']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"telegram-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--7ecc4537-89cd-4f17-8027-6e0f70710c53",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--7ecc4537-89cd-4f17-8027-6e0f70710c53"
              ],
              "labels": [
                  "misp:name=\"telegram-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--7ecc4537-89cd-4f17-8027-6e0f70710c53",
              "user_id": "1234567890",
              "account_login": "T3l3gr4mUs3r",
              "account_type": "telegram",
              "x_misp_phone": [
                  "0112233445",
                  "0556677889"
              ]
          }
      ]
      ```

- twitter-account
  - MISP
    ```json
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
                "value": "octocat.png",
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'twitter' AND user-account:display_name = 'Octo Cat' AND user-account:user_id = '1357111317' AND user-account:account_login = 'octocat' AND user-account:x_misp_followers = '666' AND user-account:x_misp_profile_image.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_profile_image.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"twitter-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb"
              ],
              "labels": [
                  "misp:name=\"twitter-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
              "user_id": "1357111317",
              "account_login": "octocat",
              "account_type": "twitter",
              "display_name": "Octo Cat",
              "x_misp_followers": "666",
              "x_misp_profile_image": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              }
          }
      ]
      ```

- url
  - MISP
    ```json
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5ac347ca-dac4-4562-9775-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[url:value = 'https://www.circl.lu/team' AND url:x_misp_domain = 'circl.lu' AND url:x_misp_host = 'www.circl.lu' AND url:x_misp_ip = '149.13.33.14' AND url:x_misp_port = '443']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"url\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac347ca-dac4-4562-9775-04120a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "url--5ac347ca-dac4-4562-9775-04120a00020f"
              ],
              "labels": [
                  "misp:name=\"url\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "url",
              "spec_version": "2.1",
              "id": "url--5ac347ca-dac4-4562-9775-04120a00020f",
              "value": "https://www.circl.lu/team",
              "x_misp_domain": "circl.lu",
              "x_misp_host": "www.circl.lu",
              "x_misp_ip": "149.13.33.14",
              "x_misp_port": "443"
          }
      ]
      ```

- user-account
  - MISP
    ```json
    {
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
                "value": "octocat.png",
                "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
            },
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
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:account_type = 'unix' AND user-account:display_name = 'Code Monkey' AND user-account:credential = 'P4ssw0rd1234!' AND user-account:user_id = 'iglocska' AND user-account:account_login = 'iglocska' AND user-account:credential_last_changed = '2020-10-25T16:22:00Z' AND user-account:extensions.'unix-account-ext'.groups = 'viktor-fan' AND user-account:extensions.'unix-account-ext'.groups = 'donald-fan' AND user-account:extensions.'unix-account-ext'.gid = '2004' AND user-account:extensions.'unix-account-ext'.home_dir = '/home/iglocska' AND user-account:x_misp_user_avatar.data = 'iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC' AND user-account:x_misp_user_avatar.value = 'octocat.png']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"user-account\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5d234f25-539c-4d12-bf93-2c46a964451a",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "user-account--5d234f25-539c-4d12-bf93-2c46a964451a"
              ],
              "labels": [
                  "misp:name=\"user-account\"",
                  "misp:meta-category=\"misc\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "user-account",
              "spec_version": "2.1",
              "id": "user-account--5d234f25-539c-4d12-bf93-2c46a964451a",
              "user_id": "iglocska",
              "credential": "P4ssw0rd1234!",
              "account_login": "iglocska",
              "account_type": "unix",
              "display_name": "Code Monkey",
              "credential_last_changed": "2020-10-25T16:22:00Z",
              "extensions": {
                  "unix-account-ext": {
                      "gid": 2004,
                      "groups": [
                          "viktor-fan",
                          "donald-fan"
                      ],
                      "home_dir": "/home/iglocska"
                  }
              },
              "x_misp_user_avatar": {
                  "value": "octocat.png",
                  "data": "iVBORw0KGgoAAAANSUhEUgA[...]hIu9Wl1AAAAAElFTkSuQmCC"
              }
          }
      ]
      ```

- vulnerability
  - MISP
    ```json
    {
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
            }
        ]
    }
    ```
  - STIX
    - Vulnerability
      ```json
      {
          "type": "vulnerability",
          "spec_version": "2.1",
          "id": "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "CVE-2017-11774",
          "description": "Microsoft Outlook allow an attacker to execute arbitrary commands",
          "labels": [
              "misp:name=\"vulnerability\"",
              "misp:meta-category=\"vulnerability\"",
              "misp:to_ids=\"False\""
          ],
          "external_references": [
              {
                  "source_name": "cve",
                  "external_id": "CVE-2017-11774"
              },
              {
                  "source_name": "url",
                  "url": "http://www.securityfocus.com/bid/101098"
              },
              {
                  "source_name": "url",
                  "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11774"
              }
          ],
          "x_misp_created": "2017-10-13T07:29:00Z",
          "x_misp_cvss_score": "6.8",
          "x_misp_published": "2017-10-13T07:29:00Z"
      }
      ```

- x509
  - MISP
    ```json
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
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--5ac3444e-145c-4749-8467-02550a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[x509-certificate:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND x509-certificate:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND x509-certificate:issuer = 'Issuer Name' AND x509-certificate:subject_public_key_algorithm = 'PublicKeyAlgorithm' AND x509-certificate:subject_public_key_exponent = '2' AND x509-certificate:subject_public_key_modulus = 'C5' AND x509-certificate:serial_number = '1234567890' AND x509-certificate:signature_algorithm = 'SHA1_WITH_RSA_ENCRYPTION' AND x509-certificate:subject = 'CertificateSubject' AND x509-certificate:version = '1' AND x509-certificate:validity_not_after = '2021-01-01T00:00:00Z' AND x509-certificate:validity_not_before = '2020-01-01T00:00:00Z' AND x509-certificate:x_misp_pem = 'RawCertificateInPEMFormat']",
          "pattern_type": "stix",
          "pattern_version": "2.1",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:name=\"x509\"",
              "misp:meta-category=\"network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      [
          {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--5ac3444e-145c-4749-8467-02550a00020f",
              "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
              "created": "2020-10-25T16:22:00.000Z",
              "modified": "2020-10-25T16:22:00.000Z",
              "first_observed": "2020-10-25T16:22:00Z",
              "last_observed": "2020-10-25T16:22:00Z",
              "number_observed": 1,
              "object_refs": [
                  "x509-certificate--5ac3444e-145c-4749-8467-02550a00020f"
              ],
              "labels": [
                  "misp:name=\"x509\"",
                  "misp:meta-category=\"network\"",
                  "misp:to_ids=\"False\""
              ]
          },
          {
              "type": "x509-certificate",
              "spec_version": "2.1",
              "id": "x509-certificate--5ac3444e-145c-4749-8467-02550a00020f",
              "hashes": {
                  "MD5": "b2a5abfeef9e36964281a31e17b57c97",
                  "SHA-1": "5898fc860300e228dcd54c0b1045b5fa0dcda502"
              },
              "version": "1",
              "serial_number": "1234567890",
              "signature_algorithm": "SHA1_WITH_RSA_ENCRYPTION",
              "issuer": "Issuer Name",
              "validity_not_before": "2020-01-01T00:00:00Z",
              "validity_not_after": "2021-01-01T00:00:00Z",
              "subject": "CertificateSubject",
              "subject_public_key_algorithm": "PublicKeyAlgorithm",
              "subject_public_key_modulus": "C5",
              "subject_public_key_exponent": 2,
              "x_misp_pem": "RawCertificateInPEMFormat"
          }
      ]
      ```

- yara
  - MISP
    ```json
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
                "value": "rule torcryptomining { meta: description = \"Tor miner - broken UPX magic string\" strings: $upx_erase = {(00 FF 99 41|DF DD 30 33)} condition: $upx_erase at 236 }"
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--cafdd27e-c3e2-4f7a-88b4-4c1c98f18be7",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Ultimate rule",
          "description": "To rule them all",
          "pattern": "rule torcryptomining { meta: description = \\\\\"Tor miner - broken UPX magic string\\\\\" strings: $upx_erase = {(00 FF 99 41|DF DD 30 33)} condition: $upx_erase at 236 }",
          "pattern_type": "yara",
          "pattern_version": "4.1.0",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:name=\"yara\"",
              "misp:meta-category=\"misc\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```


### Unmapped object names

Not all the MISP objects are mapped and exported as know STIX 2.1 objects.  
Those unmapped objects are then exported as STIX Custom objects. Here are some examples:
- bank-account
  - MISP
    ```json
    {
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
                "to_ids": true
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
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--695e7924-2518-4054-9cea-f82853d37410",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:category=\"financial\"",
            "misp:name=\"bank-account\""
        ],
        "x_misp_attributes": [
            {
                "object_relation": "iban",
                "to_ids": true,
                "type": "iban",
                "value": "LU1234567890ABCDEF1234567890"
            },
            {
                "object_relation": "swift",
                "type": "bic",
                "value": "CTBKLUPP"
            },
            {
                "object_relation": "account",
                "type": "bank-account-nr",
                "value": "1234567890"
            },
            {
                "object_relation": "institution-name",
                "type": "text",
                "value": "Central Bank"
            },
            {
                "object_relation": "account-name",
                "type": "text",
                "value": "John Smith's bank account"
            },
            {
                "object_relation": "beneficiary",
                "type": "text",
                "value": "John Smith"
            },
            {
                "object_relation": "currency-code",
                "type": "text",
                "value": "EUR"
            }
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "bank-account"
    }
    ```

- btc-wallet
  - MISP
    ```json
    {
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
                "to_ids": true
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
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:category=\"financial\"",
            "misp:name=\"btc-wallet\""
        ],
        "x_misp_attributes": [
            {
                "object_relation": "wallet-address",
                "to_ids": true,
                "type": "btc",
                "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE"
            },
            {
                "object_relation": "balance_BTC",
                "type": "float",
                "value": "2.25036953"
            },
            {
                "object_relation": "BTC_received",
                "type": "float",
                "value": "3.35036953"
            },
            {
                "object_relation": "BTC_sent",
                "type": "float",
                "value": "1.1"
            }
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "btc-wallet"
    }
    ```

- person
  - MISP
    ```json
    {
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
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--868037d5-d804-4f1d-8016-f296361f9c68",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:category=\"misc\"",
            "misp:name=\"person\""
        ],
        "x_misp_attributes": [
            {
                "object_relation": "first-name",
                "type": "first-name",
                "value": "John"
            },
            {
                "object_relation": "last-name",
                "type": "last-name",
                "value": "Smith"
            },
            {
                "object_relation": "nationality",
                "type": "nationality",
                "value": "USA"
            },
            {
                "object_relation": "passport-number",
                "type": "passport-number",
                "value": "ABA9875413"
            },
            {
                "object_relation": "phone-number",
                "type": "phone-number",
                "value": "0123456789"
            }
        ],
        "x_misp_meta_category": "misc",
        "x_misp_name": "person"
    }
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX 2.1 mapping](misp_events_to_stix21.md)
- [Attributes export to STIX 2.1 mapping](misp_attributes_to_stix21.md)
- [Galaxies export to STIX 2.1 mapping](misp_galaxies_to_stix21.md)

([Go back to the main documentation](README.md))
