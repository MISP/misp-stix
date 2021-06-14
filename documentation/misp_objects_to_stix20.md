# MISP Objects to STIX1 mapping

MISP Objects are containers of single MISP attributes that are grouped together to highlight their meaning in a real use case scenario.
For instance, if you want to share a report with suspicious files, without object templates you would end up with a list of file names, hashes, and other attributes that are all mixed together, making the differentiation of each file difficult. In this case with the file object template, we simply group together all the attributes which belong to each file.
The list of currently supported templates is available [here](https://github.com/MISP/misp-objects).

As we can see in the [detailed Events mapping documentation](misp_events_to_stix20.md), objects within their event are exported in different STIX 2.0 objects embedded in a `STIX Bundle`. Those objects' references are also embedded within the report `object_refs` field.  
For the rest of this documentation, we will then, in order to keep the content clear enough and to skip the irrelevant part, consider the followings:
- MISP Objects are exported as Indicator or Observed Data object in most of the cases, depending on the `to_ids` flag:
  - If any `to_ids` flag is set in an object attribute, the object is exported as an Indicator.
  - If no `to_ids` flag is set, the object is exported as an Observed Data
  - Some objects are not exported either as Indicator nor as Observed Data.

### Current mapping

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
          "id": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[autonomous-system:number = '66642' AND autonomous-system:name = 'AS name' AND autonomous-system:x_misp_subnet_announced = '1.2.3.4' AND autonomous-system:x_misp_subnet_announced = '8.8.8.8']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"asn\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "autonomous-system",
                  "number": 66642,
                  "name": "AS name",
                  "x_misp_subnet_announced": [
                      "1.2.3.4",
                      "8.8.8.8"
                  ]
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"asn\"",
              "misp:to_ids=\"False\""
          ]
      }
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
            }
        ]
    }
    ```
  - STIX
    - Attack Pattern
      ```json
      {
          "type": "attack-pattern",
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
              "misp:category=\"vulnerability\"",
              "misp:name=\"attack-pattern\""
          ],
          "external_references": [
              {
                  "source_name": "capec",
                  "external_id": "CAPEC-9"
              }
          ]
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
          "id": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "Block traffic to PIVY C2 Server (10.10.10.10)",
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"course-of-action\""
          ],
          "x_misp_cost": "Low",
          "x_misp_efficacy": "High",
          "x_misp_impact": "Low",
          "x_misp_objective": "Block communication between the PIVY agents and the C2 Server",
          "x_misp_stage": "Response",
          "x_misp_type": "Perimeter Blocking"
      }
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
          "id": "indicator--5b1f9378-46d4-494b-a4c1-044e0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[user-account:user_id = 'misp' AND user-account:credential = 'Password1234' AND user-account:x_misp_text = 'MISP default credentials' AND user-account:x_misp_type = 'password' AND user-account:x_misp_origin = 'malware-analysis' AND user-account:x_misp_format = 'clear-text' AND user-account:x_misp_notification = 'victim-notified']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"credential\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5b1f9378-46d4-494b-a4c1-044e0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "user-account",
                  "user_id": "misp",
                  "credential": "Password1234",
                  "x_misp_format": "clear-text",
                  "x_misp_notification": "victim-notified",
                  "x_misp_origin": "malware-analysis",
                  "x_misp_text": "MISP default credentials",
                  "x_misp_type": "password"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"credential\"",
              "misp:to_ids=\"False\""
          ]
      }
      ```

- domain-ip
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5ac337df-e078-4e99-8b17-02550a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[domain-name:value = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"domain-ip\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac337df-e078-4e99-8b17-02550a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu",
                  "resolves_to_refs": [
                      "1"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "149.13.33.14"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"domain-ip\"",
              "misp:to_ids=\"False\""
          ]
      }
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
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5e396622-2a54-4c8d-b61d-159da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "pattern": "[email-message:cc_refs.value = 'cc1@email.test' AND email-message:cc_refs.value = 'cc2@email.test' AND email-message:from_ref.value = 'source@email.test' AND email-message:additional_header_fields.reply_to = 'reply-to@email.test' AND email-message:subject = 'Email test subject' AND email-message:to_refs.value = 'destination@email.test' AND email-message:additional_header_fields.x_mailer = 'x-mailer-test' AND email-message:body_multipart[0].body_raw_ref.name = 'attachment1.file' AND email-message:body_multipart[1].body_raw_ref.name = 'attachment2.file' AND email-message:x_misp_user_agent = 'Test user agent' AND email-message:x_misp_mime_boundary = 'Test mime boundary']",
          "valid_from": "2021-06-11T21:05:48Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"email\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5e396622-2a54-4c8d-b61d-159da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "first_observed": "2021-06-11T21:05:48Z",
          "last_observed": "2021-06-11T21:05:48Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": true,
                  "from_ref": "1",
                  "to_refs": [
                      "2"
                  ],
                  "cc_refs": [
                      "3",
                      "4"
                  ],
                  "subject": "Email test subject",
                  "additional_header_fields": {
                      "Reply-To": "reply-to@email.test",
                      "X-Mailer": "x-mailer-test"
                  },
                  "body_multipart": [
                      {
                          "body_raw_ref": "5",
                          "content_disposition": "attachment; filename='attachment1.file'"
                      },
                      {
                          "body_raw_ref": "6",
                          "content_disposition": "attachment; filename='attachment2.file'"
                      }
                  ],
                  "x_misp_mime_boundary": "Test mime boundary",
                  "x_misp_user_agent": "Test user agent"
              },
              "1": {
                  "type": "email-addr",
                  "value": "source@email.test"
              },
              "2": {
                  "type": "email-addr",
                  "value": "destination@email.test"
              },
              "3": {
                  "type": "email-addr",
                  "value": "cc1@email.test"
              },
              "4": {
                  "type": "email-addr",
                  "value": "cc2@email.test"
              },
              "5": {
                  "type": "file",
                  "name": "attachment1.file"
              },
              "6": {
                  "type": "file",
                  "name": "attachment2.file"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"email\"",
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
                "value": "marcopolo"
            },
            {
                "type": "link",
                "object_relation": "link",
                "value": "https://facebook.com/marcopolo"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T22:00:03.000Z",
          "modified": "2021-06-11T22:00:03.000Z",
          "pattern": "[user-account:account_type = 'facebook' AND user-account:user_id = '1392781243' AND user-account:account_login = 'marcopolo' AND user-account:x_misp_link = 'https://facebook.com/marcopolo']",
          "valid_from": "2021-06-11T22:00:03Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"facebook-account\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T22:00:03.000Z",
          "modified": "2021-06-11T22:00:03.000Z",
          "first_observed": "2021-06-11T22:00:03Z",
          "last_observed": "2021-06-11T22:00:03Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "user-account",
                  "user_id": "1392781243",
                  "account_login": "marcopolo",
                  "account_type": "facebook",
                  "x_misp_link": "https://facebook.com/marcopolo"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"facebook-account\"",
              "misp:to_ids=\"False\""
          ]
      }
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "pattern": "[file:hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86' AND file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b' AND file:name = 'oui' AND file:name_enc = 'UTF-8' AND file:size = '35' AND file:parent_directory_ref.path = '/var/www/MISP/app/files/scripts/tmp' AND (file:content_ref.payload_bin = 'UEsDBAoACQAAAPKLQ1AvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAA+dKOF7nSjhedXgLAAEEIQAAAAQhAAAA7ukeownnAQsmsimPVT3qvMUSCRqPjj3xfZpK3MTLpCrssX1AVtxZoMh3ucu5mCxQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAPKLQ1BAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAPnSjhe50o4XnV4CwABBCEAAAAEIQAAAFHTwHeSOtOjQMWS6+0aN1BLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAADyi0NQL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAA+dKOF51eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAADyi0NQQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAPnSjhedXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==' AND file:content_ref.x_misp_filename = 'oui' AND file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802') AND (file:content_ref.payload_bin = 'Tm9uLW1hbGljaW91cyBmaWxlCg==' AND file:content_ref.x_misp_filename = 'non')]",
          "valid_from": "2021-06-11T21:05:48Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "first_observed": "2021-06-11T21:05:48Z",
          "last_observed": "2021-06-11T21:05:48Z",
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
                  "payload_bin": "UEsDBAoACQAAAPKLQ1AvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAA+dKOF7nSjhedXgLAAEEIQAAAAQhAAAA7ukeownnAQsmsimPVT3qvMUSCRqPjj3xfZpK3MTLpCrssX1AVtxZoMh3ucu5mCxQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAPKLQ1BAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAPnSjhe50o4XnV4CwABBCEAAAAEIQAAAFHTwHeSOtOjQMWS6+0aN1BLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAADyi0NQL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAA+dKOF51eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAADyi0NQQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAPnSjhedXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
                  "hashes": {
                      "MD5": "8764605c6f388c89096b534d33565802"
                  },
                  "x_misp_filename": "oui"
              },
              "3": {
                  "type": "artifact",
                  "payload_bin": "Tm9uLW1hbGljaW91cyBmaWxlCg==",
                  "x_misp_filename": "non"
              }
          },
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"file\"",
              "misp:to_ids=\"False\""
          ]
      }
      ```

- file with pe and pe-sectino
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
          "id": "indicator--5ac47782-e1b8-40b6-96b4-02510a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND file:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND file:hashes.SHA256 = '3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8' AND file:name = 'oui' AND file:size = '1234' AND file:x_misp_entropy = '1.234' AND file:extensions.'windows-pebinary-ext'.imphash = '23ea835ab4b9017c74dfb023d2301c99' AND file:extensions.'windows-pebinary-ext'.number_of_sections = '8' AND file:extensions.'windows-pebinary-ext'.pe_type = 'exe' AND file:extensions.'windows-pebinary-ext'.optional_header.address_of_entry_point = '5369222868' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2019-03-16T12:31:22' AND file:extensions.'windows-pebinary-ext'.x_misp_original_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_internal_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_file_description = 'SSH, Telnet and Rlogin client' AND file:extensions.'windows-pebinary-ext'.x_misp_file_version = 'Release 0.71 (with embedded help)' AND file:extensions.'windows-pebinary-ext'.x_misp_lang_id = '080904B0' AND file:extensions.'windows-pebinary-ext'.x_misp_product_name = 'PuTTy suite' AND file:extensions.'windows-pebinary-ext'.x_misp_product_version = 'Release 0.71' AND file:extensions.'windows-pebinary-ext'.x_misp_company_name = 'Simoe Tatham' AND file:extensions.'windows-pebinary-ext'.x_misp_legal_copyright = 'Copyright \u00a9 1997-2019 Simon Tatham.' AND file:extensions.'windows-pebinary-ext'.x_misp_impfuzzy = '192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt' AND file:extensions.'windows-pebinary-ext'.sections[0].entropy = '7.836462238824369' AND file:extensions.'windows-pebinary-ext'.sections[0].name = '.rsrc' AND file:extensions.'windows-pebinary-ext'.sections[0].size = '305152' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.MD5 = '8a2a5fc2ce56b3b04d58539a95390600' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA1 = '0aeb9def096e9f73e9460afe6f8783a32c7eabdf' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA256 = 'c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA512 = '98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SSDEEP = '6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"file\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac47782-e1b8-40b6-96b4-02510a00020f",
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
                                      "ssdeep": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                                  }
                              }
                          ],
                          "x_misp_company_name": "Simoe Tatham",
                          "x_misp_compilation_timestamp": "2019-03-16T12:31:22",
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
          },
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"file\"",
              "misp:to_ids=\"False\""
          ]
      }
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
          "id": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '149.13.33.14') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '443' AND network-traffic:start = '2020-10-25T16:22:00Z']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"ip-port\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac47edc-31e4-4402-a7b6-040d0a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "start": "2020-10-25T16:22:00Z",
                  "dst_ref": "1",
                  "dst_port": 443,
                  "protocols": [
                      "ipv4",
                      "tcp"
                  ],
                  "x_misp_domain": "circl.lu"
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "149.13.33.14"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"ip-port\"",
              "misp:to_ids=\"False\""
          ]
      }
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
          "id": "indicator--b0f55591-6a63-4fbd-a169-064e64738d95",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[mutex:name = 'MutexTest' AND mutex:x_misp_description = 'Test mutex on unix' AND mutex:x_misp_operating_system = 'Unix']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"mutex\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--b0f55591-6a63-4fbd-a169-064e64738d95",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "mutex",
                  "name": "MutexTest",
                  "x_misp_description": "Test mutex on unix",
                  "x_misp_operating_system": "Unix"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"mutex\"",
              "misp:to_ids=\"False\""
          ]
      }
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
          "id": "indicator--5afacc53-c0b0-4825-a6ee-03c80a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '8080' AND network-traffic:src_port = '8080' AND network-traffic:protocols[0] = 'IP' AND network-traffic:protocols[1] = 'TCP' AND network-traffic:protocols[2] = 'HTTP']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"network-connection\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5afacc53-c0b0-4825-a6ee-03c80a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "src_ref": "1",
                  "dst_ref": "2",
                  "src_port": 8080,
                  "dst_port": 8080,
                  "protocols": [
                      "IP",
                      "TCP",
                      "HTTP"
                  ],
                  "x_misp_hostname_dst": "circl.lu"
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              },
              "2": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"network-connection\"",
              "misp:to_ids=\"False\""
          ]
      }
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
          "id": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:dst_port = '8080' AND network-traffic:src_port = '8080' AND network-traffic:protocols[0] = 'TCP' AND network-traffic:extensions.'socket-ext'.address_family = 'AF_INET' AND network-traffic:extensions.'socket-ext'.socket_type = 'SOCK_RAW' AND network-traffic:extensions.'socket-ext'.protocol_family = 'PF_INET' AND network-traffic:extensions.'socket-ext'.is_listening = true]",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"network-socket\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5afb3223-0988-4ef1-a920-02070a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "src_ref": "1",
                  "dst_ref": "2",
                  "src_port": 8080,
                  "dst_port": 8080,
                  "protocols": [
                      "TCP"
                  ],
                  "extensions": {
                      "socket-ext": {
                          "address_family": "AF_INET",
                          "is_listening": true,
                          "protocol_family": "PF_INET",
                          "socket_type": "SOCK_RAW"
                      }
                  },
                  "x_misp_hostname_dst": "circl.lu"
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              },
              "2": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"network-socket\"",
              "misp:to_ids=\"False\""
          ]
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
                "type": "text",
                "object_relation": "pid",
                "value": "2510"
            },
            {
                "type": "text",
                "object_relation": "child-pid",
                "value": "1401"
            },
            {
                "type": "text",
                "object_relation": "parent-pid",
                "value": "2107"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "test_process.exe"
            },
            {
                "type": "filename",
                "object_relation": "image",
                "value": "TestProcess"
            },
            {
                "type": "port",
                "object_relation": "port",
                "value": "1234"
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5e39776a-b284-40b3-8079-22fea964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[process:pid = '2510' AND process:name = 'test_process.exe' AND process:image_ref.name = 'TestProcess' AND process:parent_ref.pid = '2107' AND process:child_refs[0].pid = '1401' AND process:x_misp_port = '1234']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"process\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5e39776a-b284-40b3-8079-22fea964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "process",
                  "pid": 2510,
                  "name": "test_process.exe",
                  "parent_ref": "1",
                  "child_refs": [
                      "2"
                  ],
                  "image_ref": "3",
                  "x_misp_port": "1234"
              },
              "1": {
                  "type": "process",
                  "pid": 2107
              },
              "2": {
                  "type": "process",
                  "pid": 1401
              },
              "3": {
                  "type": "file",
                  "name": "TestProcess"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"process\"",
              "misp:to_ids=\"False\""
          ]
      }
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
                "value": "qwertyuiop"
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5ac3379c-3e74-44ba-9160-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[windows-registry-key:key = 'hkey_local_machine\\\\system\\\\bar\\\\foo' AND windows-registry-key:modified = '2020-10-25T16:22:00' AND windows-registry-key:values[0].data = 'qwertyuiop' AND windows-registry-key:values[0].data_type = 'REG_SZ' AND windows-registry-key:values[0].name = 'RegistryName' AND windows-registry-key:x_misp_hive = 'hklm']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "file"
              }
          ],
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"registry-key\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac3379c-3e74-44ba-9160-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "hkey_local_machine\\system\\bar\\foo",
                  "values": [
                      {
                          "name": "RegistryName",
                          "data": "qwertyuiop",
                          "data_type": "REG_SZ"
                      }
                  ],
                  "modified": "2020-10-25T16:22:00Z",
                  "x_misp_hive": "hklm"
              }
          },
          "labels": [
              "misp:category=\"file\"",
              "misp:name=\"registry-key\"",
              "misp:to_ids=\"False\""
          ]
      }
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
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T22:00:03.000Z",
          "modified": "2021-06-11T22:00:03.000Z",
          "pattern": "[user-account:account_type = 'twitter' AND user-account:display_name = 'John Doe' AND user-account:user_id = '1357111317' AND user-account:account_login = 'johndoe' AND user-account:x_misp_followers = '666']",
          "valid_from": "2021-06-11T22:00:03Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"twitter-account\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T22:00:03.000Z",
          "modified": "2021-06-11T22:00:03.000Z",
          "first_observed": "2021-06-11T22:00:03Z",
          "last_observed": "2021-06-11T22:00:03Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "user-account",
                  "user_id": "1357111317",
                  "account_login": "johndoe",
                  "account_type": "twitter",
                  "display_name": "John Doe",
                  "x_misp_followers": "666"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"twitter-account\"",
              "misp:to_ids=\"False\""
          ]
      }
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
          "id": "indicator--5ac347ca-dac4-4562-9775-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[url:value = 'https://www.circl.lu/team' AND url:x_misp_domain = 'circl.lu' AND url:x_misp_host = 'www.circl.lu' AND url:x_misp_ip = '149.13.33.14' AND url:x_misp_port = '443']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"url\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac347ca-dac4-4562-9775-04120a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "url",
                  "value": "https://www.circl.lu/team",
                  "x_misp_domain": "circl.lu",
                  "x_misp_host": "www.circl.lu",
                  "x_misp_ip": "149.13.33.14",
                  "x_misp_port": "443"
              }
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"url\"",
              "misp:to_ids=\"False\""
          ]
      }
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
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "pattern": "[user-account:account_type = 'unix' AND user-account:display_name = 'Code Monkey' AND user-account:user_id = 'iglocska' AND user-account:account_login = 'iglocska' AND user-account:password_last_changed = '2020-10-25T16:22:00' AND user-account:extensions.'unix-account-ext'.groups = 'viktor-fan' AND user-account:extensions.'unix-account-ext'.groups = 'donald-fan' AND user-account:extensions.'unix-account-ext'.gid = '2004' AND user-account:extensions.'unix-account-ext'.home_dir = '/home/iglocska' AND user-account:x_misp_password = 'P4ssw0rd1234!']",
          "valid_from": "2021-06-11T21:05:48Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "misc"
              }
          ],
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"user-account\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5d234f25-539c-4d12-bf93-2c46a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "first_observed": "2021-06-11T21:05:48Z",
          "last_observed": "2021-06-11T21:05:48Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "user-account",
                  "user_id": "iglocska",
                  "account_login": "iglocska",
                  "account_type": "unix",
                  "display_name": "Code Monkey",
                  "password_last_changed": "2020-10-25T16:22:00Z",
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
                  "x_misp_password": "P4ssw0rd1234!"
              }
          },
          "labels": [
              "misp:category=\"misc\"",
              "misp:name=\"user-account\"",
              "misp:to_ids=\"False\""
          ]
      }
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
            }
        ]
    }
    ```
  - STIX
    - Vulnerability
      ```json
      {
          "type": "vulnerability",
          "id": "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2017-10-13T07:29:00.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "name": "CVE-2017-11774",
          "description": "Microsoft Outlook allow an attacker to execute arbitrary commands",
          "labels": [
              "misp:category=\"vulnerability\"",
              "misp:name=\"vulnerability\""
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
          "x_misp_cvss_score": "6.8",
          "x_misp_published": "2017-10-13T07:29:00"
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
                "object_relation": "signature-algorithm",
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
            }
        ]
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--5ac3444e-145c-4749-8467-02550a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "pattern": "[x509-certificate:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND x509-certificate:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND x509-certificate:issuer = 'Issuer Name' AND x509-certificate:subject_public_key_algorithm = 'PublicKeyAlgorithm' AND x509-certificate:subject_public_key_exponent = '2' AND x509-certificate:subject_public_key_modulus = 'C5' AND x509-certificate:serial_number = '1234567890' AND x509-certificate:signature_algorithm = 'SHA1_WITH_RSA_ENCRYPTION' AND x509-certificate:subject = 'CertificateSubject' AND x509-certificate:version = '1' AND x509-certificate:validity_not_after = '2021-01-01T00:00:00' AND x509-certificate:validity_not_before = '2020-01-01T00:00:00' AND x509-certificate:x_misp_pem = 'RawCertificateInPEMFormat']",
          "valid_from": "2021-06-11T21:05:48Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "network"
              }
          ],
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"x509\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--5ac3444e-145c-4749-8467-02550a00020f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2021-06-11T21:05:48.000Z",
          "modified": "2021-06-11T21:05:48.000Z",
          "first_observed": "2021-06-11T21:05:48Z",
          "last_observed": "2021-06-11T21:05:48Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
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
          },
          "labels": [
              "misp:category=\"network\"",
              "misp:name=\"x509\"",
              "misp:to_ids=\"False\""
          ]
      }
      ```


### Unmapped object names

Not all the MISP objects are mapped and exported as know STIX 2.0 objects.  
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
- [Events export to STIX 2.0 mapping](misp_events_to_stix20.md)
- [Attributes export to STIX 2.0 mapping](misp_attributes_to_stix20.md)
- [Galaxies export to STIX 2.0 mapping](misp_galaxies_to_stix20.md)

([Go back to the main documentation](README.md))
