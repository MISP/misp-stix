# MISP Attributes to STIX 2.0 mapping

MISP Attributes are the actual raw data used by analysts to describe the IoCs and observed data related to a specific event (which could be an actual threat report, an IP watchlist, etc.)
Thus, in most of the cases, a MISP Attribute is exported to STIX as `Indicator` if its `to_ids` flag is set, or as `Observable` if its `to_ids` flag is false. But there are also some other examples where MISP attributes are exported neither as indicator nor as observable, this documentation gives all the details about the single attributes mapping into STIX objects, depending on the type of the attributes.

As we can see in the [detailed Events mapping documentation](misp_events_to_stix20.md), attributes within their event are exported in different STIX 2.0 objects embedded in a `STIX Bundle`. Those objects' references are also embedded within the report `object_refs` field.  
For the rest of this documentation, we will then, in order to keep the content clear enough and to skip the irrelevant part, consider the followings:
- Attributes are exported as Indicator or Observed Data objects in most of the cases depending on the `to_ids` flag:
  - If an attribute is associated with an Indicator object, it means it is exported with the `to_ids` flag set to `True`.
  - If there is an Observed Data with the attribute, it means it is exported with the `to_ids` flag unset (`False`).
  - If neither an Indicator nor an Observed Data object is documented for a given attribute, the `to_ids` flag does not matter because the attribute is never going to be exported as Indicator nor Observed Data.

### Current mapping

- AS
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "AS",
        "category": "Network activity",
        "timestamp": "1603642920",
        "value": "AS174"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[autonomous-system:number = '174']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"AS\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "autonomous-system",
                  "number": 174
              }
          },
          "labels": [
              "misp:type=\"AS\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "autonomous-system",
                  "number": 174
              }
          },
          "labels": [
              "misp:type=\"AS\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- attachment
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "attachment",
        "category": "Payload delivery",
        "value": "attachment.test",
        "data": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:name = 'attachment.test' AND file:content_ref.payload_bin = 'ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"attachment\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "file",
                  "name": "attachment.test",
                  "content_ref": "1"
              },
              "1": {
                  "type": "artifact",
                  "payload_bin": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK"
              }
          },
          "labels": [
              "misp:type=\"attachment\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "file",
                  "name": "attachment.test",
                  "content_ref": "1"
              },
              "1": {
                  "type": "artifact",
                  "payload_bin": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK"
              }
          },
          "labels": [
              "misp:type=\"attachment\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- campaign-name
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "campaign-name",
        "category": "Attribution",
        "value": "MartyMcFly",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Campaign
      ```json
      {
          "type": "campaign",
          "id": "campaign--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "MartyMcFly",
          "labels": [
              "misp:type=\"campaign-name\"",
              "misp:category=\"Attribution\""
          ]
      }
      ```

- domain
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "domain",
        "category": "Network activity",
        "value": "circl.lu",
        "timestamp": "1603642920",
        "comment": "Domain test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Domain test attribute",
          "pattern": "[domain-name:value = 'circl.lu']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"domain\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              }
          },
          "labels": [
              "misp:type=\"domain\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              }
          },
          "labels": [
              "misp:type=\"domain\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- domain|ip
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "domain|ip",
        "category": "Network activity",
        "value": "circl.lu|149.13.33.14",
        "timestamp": "1603642920",
        "comment": "Domain|ip test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Domain|ip test attribute",
          "pattern": "[domain-name:value = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"domain|ip\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
              "misp:type=\"domain|ip\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
              "misp:type=\"domain|ip\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- email
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email",
        "category": "Payload delivery",
        "value": "address@email.test",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-addr:value = 'address@email.test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-addr",
                  "value": "address@email.test"
              }
          },
          "labels": [
              "misp:type=\"email\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-addr",
                  "value": "address@email.test"
              }
          },
          "labels": [
              "misp:type=\"email\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-attachment
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-attachment",
        "category": "Payload delivery",
        "value": "email_attachment.test",
        "timestamp": "1603642920",
        "comment": "Email attachment test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Email attachment test attribute",
          "pattern": "[email-message:body_multipart[*].body_raw_ref.name = 'email_attachment.test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-attachment\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": true,
                  "body_multipart": [
                      {
                          "body_raw_ref": "1",
                          "content_disposition": "attachment; filename='email_attachment.test'"
                      }
                  ]
              },
              "1": {
                  "type": "file",
                  "name": "email_attachment.test"
              }
          },
          "labels": [
              "misp:type=\"email-attachment\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": true,
                  "body_multipart": [
                      {
                          "body_raw_ref": "1",
                          "content_disposition": "attachment; filename='email_attachment.test'"
                      }
                  ]
              },
              "1": {
                  "type": "file",
                  "name": "email_attachment.test"
              }
          },
          "labels": [
              "misp:type=\"email-attachment\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-body
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-body",
        "category": "Payload delivery",
        "value": "Email body test",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:body = 'Email body test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-body\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "body": "Email body test"
              }
          },
          "labels": [
              "misp:type=\"email-body\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "body": "Email body test"
              }
          },
          "labels": [
              "misp:type=\"email-body\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-dst
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "email-dst",
        "category": "Payload delivery",
        "value": "dst@email.test",
        "timestamp": "1603642920",
        "comment": "Destination email address test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Destination email address test attribute",
          "pattern": "[email-message:to_refs[*].value = 'dst@email.test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-dst\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "to_refs": [
                      "1"
                  ]
              },
              "1": {
                  "type": "email-addr",
                  "value": "dst@email.test"
              }
          },
          "labels": [
              "misp:type=\"email-dst\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "to_refs": [
                      "1"
                  ]
              },
              "1": {
                  "type": "email-addr",
                  "value": "dst@email.test"
              }
          },
          "labels": [
              "misp:type=\"email-dst\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-header
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-header",
        "category": "Payload delivery",
        "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:received_lines = 'from mail.example.com ([198.51.100.3]) by smtp.gmail.com']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-header\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "received_lines": [
                      "from mail.example.com ([198.51.100.3]) by smtp.gmail.com"
                  ]
              }
          },
          "labels": [
              "misp:type=\"email-header\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "received_lines": [
                      "from mail.example.com ([198.51.100.3]) by smtp.gmail.com"
                  ]
              }
          },
          "labels": [
              "misp:type=\"email-header\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-reply-to
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "email-reply-to",
        "category": "Payload delivery",
        "value": "reply-to@email.test",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:additional_header_fields.reply_to = 'reply-to@email.test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-reply-to\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "additional_header_fields": {
                      "Reply-To": "reply-to@email.test"
                  }
              }
          },
          "labels": [
              "misp:type=\"email-reply-to\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "additional_header_fields": {
                      "Reply-To": "reply-to@email.test"
                  }
              }
          },
          "labels": [
              "misp:type=\"email-reply-to\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-src
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-src",
        "category": "Payload delivery",
        "value": "src@email.test",
        "timestamp": "1603642920",
        "comment": "Source email address test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Source email address test attribute",
          "pattern": "[email-message:from_ref.value = 'src@email.test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-src\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "from_ref": "1"
              },
              "1": {
                  "type": "email-addr",
                  "value": "src@email.test"
              }
          },
          "labels": [
              "misp:type=\"email-src\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "from_ref": "1"
              },
              "1": {
                  "type": "email-addr",
                  "value": "src@email.test"
              }
          },
          "labels": [
              "misp:type=\"email-src\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-subject
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "email-subject",
        "category": "Payload delivery",
        "value": "Test Subject",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:subject = 'Test Subject']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-subject\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "subject": "Test Subject"
              }
          },
          "labels": [
              "misp:type=\"email-subject\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "subject": "Test Subject"
              }
          },
          "labels": [
              "misp:type=\"email-subject\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- email-x-mailer
  - MISP
    ```json
    {
        "uuid": "f09d8496-e2ba-4250-878a-bec9b85c7e96",
        "type": "email-x-mailer",
        "category": "Payload delivery",
        "value": "Email X-Mailer test",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--f09d8496-e2ba-4250-878a-bec9b85c7e96",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[email-message:additional_header_fields.x_mailer = 'Email X-Mailer test']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"email-x-mailer\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f09d8496-e2ba-4250-878a-bec9b85c7e96",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "additional_header_fields": {
                      "X-Mailer": "Email X-Mailer test"
                  }
              }
          },
          "labels": [
              "misp:type=\"email-x-mailer\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f09d8496-e2ba-4250-878a-bec9b85c7e96",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "email-message",
                  "is_multipart": false,
                  "additional_header_fields": {
                      "X-Mailer": "Email X-Mailer test"
                  }
              }
          },
          "labels": [
              "misp:type=\"email-x-mailer\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename",
        "category": "Payload delivery",
        "value": "test_file_name",
        "timestamp": "1603642920",
        "comment": "Filename test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename test attribute",
          "pattern": "[file:name = 'test_file_name']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "file",
                  "name": "test_file_name"
              }
          },
          "labels": [
              "misp:type=\"filename\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "file",
                  "name": "test_file_name"
              }
          },
          "labels": [
              "misp:type=\"filename\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|md5",
        "category": "Payload delivery",
        "value": "filename1|b2a5abfeef9e36964281a31e17b57c97",
        "timestamp": "1603642920",
        "comment": "Filename|md5 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|md5 test attribute",
          "pattern": "[file:name = 'filename1' AND file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|md5\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                  },
                  "name": "filename1"
              }
          },
          "labels": [
              "misp:type=\"filename|md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                  },
                  "name": "filename1"
              }
          },
          "labels": [
              "misp:type=\"filename|md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha1
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "filename|sha1",
        "category": "Payload delivery",
        "value": "filename2|2920d5e6c579fce772e5506caf03af65579088bd",
        "timestamp": "1603642920",
        "comment": "Filename|sha1 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha1 test attribute",
          "pattern": "[file:name = 'filename2' AND file:hashes.SHA1 = '2920d5e6c579fce772e5506caf03af65579088bd']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha1\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
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
                      "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                  },
                  "name": "filename2"
              }
          },
          "labels": [
              "misp:type=\"filename|sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
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
                      "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                  },
                  "name": "filename2"
              }
          },
          "labels": [
              "misp:type=\"filename|sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha224
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "filename|sha224",
        "category": "Payload delivery",
        "value": "filename3|5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9",
        "timestamp": "1603642920",
        "comment": "Filename|sha224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha224 test attribute",
          "pattern": "[file:name = 'filename3' AND file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
                      "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                  },
                  "name": "filename3"
              }
          },
          "labels": [
              "misp:type=\"filename|sha224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
                      "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                  },
                  "name": "filename3"
              }
          },
          "labels": [
              "misp:type=\"filename|sha224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha256",
        "category": "Payload delivery",
        "value": "testfile.name|ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "filename|sha256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "filename|sha256 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha3-224
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "filename|sha3-224",
        "category": "Payload delivery",
        "value": "testfile.name|3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618",
        "timestamp": "1603642920",
        "comment": "Filename|sha3-224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha3-224 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA3224 = '3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha3-224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-224": "3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha3-224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha3-256
  - MISP
    ```json
    {
        "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "type": "filename|sha3-256",
        "category": "Payload delivery",
        "value": "filename5|39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4",
        "timestamp": "1603642920",
        "comment": "Filename|sha3-256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha3-256 test attribute",
          "pattern": "[file:name = 'filename5' AND file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha3-256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
                      "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
                  },
                  "name": "filename5"
              }
          },
          "labels": [
              "misp:type=\"filename|sha3-256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
                      "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
                  },
                  "name": "filename5"
              }
          },
          "labels": [
              "misp:type=\"filename|sha3-256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha3-384
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "filename|sha3-384",
        "category": "Payload delivery",
        "value": "testfile.name|93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568",
        "timestamp": "1603642920",
        "comment": "Filename|sha3-384 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha3-384 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA3384 = '93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha3-384\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-384": "93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha3-384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha3-512
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "filename|sha3-512",
        "category": "Payload delivery",
        "value": "testfile.name|fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748",
        "timestamp": "1603642920",
        "comment": "Filename|sha3-512 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha3-512 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA3512 = 'fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha3-512\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-512": "fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha3-512\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha384
  - MISP
    ```json
    {
        "uuid": "90bd7dae-b78c-4025-9073-568950c780fb",
        "type": "filename|sha384",
        "category": "Payload delivery",
        "value": "filename6|ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce",
        "timestamp": "1603642920",
        "comment": "Filename|sha384 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha384 test attribute",
          "pattern": "[file:name = 'filename6' AND file:hashes.SHA384 = 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha384\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
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
                      "SHA-384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
                  },
                  "name": "filename6"
              }
          },
          "labels": [
              "misp:type=\"filename|sha384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
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
                      "SHA-384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
                  },
                  "name": "filename6"
              }
          },
          "labels": [
              "misp:type=\"filename|sha384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha512
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha512",
        "category": "Payload delivery",
        "value": "testfile.name|06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5",
        "timestamp": "1603642920",
        "comment": "filename|sha512 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "filename|sha512 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA512 = '06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha512\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-512": "06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha512\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha512/224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha512/224",
        "category": "Payload delivery",
        "value": "testfile.name|2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc",
        "timestamp": "1603642920",
        "comment": "filename|sha512/224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "filename|sha512/224 test attribute",
          "pattern": "[file:name = 'testfile.name' AND file:hashes.SHA224 = '2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha512/224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-224": "2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc"
                  },
                  "name": "testfile.name"
              }
          },
          "labels": [
              "misp:type=\"filename|sha512/224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|sha512/256
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "filename|sha512/256",
        "category": "Payload delivery",
        "value": "filename4|82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93",
        "timestamp": "1603642920",
        "comment": "Filename|sha512/256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|sha512/256 test attribute",
          "pattern": "[file:name = 'filename4' AND file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|sha512/256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                  },
                  "name": "filename4"
              }
          },
          "labels": [
              "misp:type=\"filename|sha512/256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                  },
                  "name": "filename4"
              }
          },
          "labels": [
              "misp:type=\"filename|sha512/256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|ssdeep
  - MISP
    ```json
    {
        "uuid": "2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "type": "filename|ssdeep",
        "category": "Payload delivery",
        "value": "filename7|96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi",
        "timestamp": "1603642920",
        "comment": "Filename|ssdeep test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|ssdeep test attribute",
          "pattern": "[file:name = 'filename7' AND file:hashes.SSDEEP = '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|ssdeep\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
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
                      "ssdeep": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
                  },
                  "name": "filename7"
              }
          },
          "labels": [
              "misp:type=\"filename|ssdeep\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
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
                      "ssdeep": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
                  },
                  "name": "filename7"
              }
          },
          "labels": [
              "misp:type=\"filename|ssdeep\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- filename|tlsh
  - MISP
    ```json
    {
        "uuid": "2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "type": "filename|tlsh",
        "category": "Payload delivery",
        "value": "filename8|c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297",
        "timestamp": "1603642920",
        "comment": "Filename|tlsh test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Filename|tlsh test attribute",
          "pattern": "[file:name = 'filename8' AND file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"filename|tlsh\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
                      "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
                  },
                  "name": "filename8"
              }
          },
          "labels": [
              "misp:type=\"filename|tlsh\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
                      "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
                  },
                  "name": "filename8"
              }
          },
          "labels": [
              "misp:type=\"filename|tlsh\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- github-username
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "github-username",
        "category": "Social network",
        "value": "chrisr3d",
        "timestamp": "1603642920",
        "comment": "Github username test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Github username test attribute",
          "pattern": "[user-account:account_type = 'github' AND user-account:account_login = 'chrisr3d']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Social network"
              }
          ],
          "labels": [
              "misp:type=\"github-username\"",
              "misp:category=\"Social network\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "x-misp-attribute",
          "id": "x-misp-attribute--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "labels": [
              "misp:type=\"github-username\"",
              "misp:category=\"Social network\""
          ],
          "x_misp_category": "Social network",
          "x_misp_comment": "Github username test attribute",
          "x_misp_type": "github-username",
          "x_misp_value": "chrisr3d"
      }
      ```

- hostname
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "hostname",
        "category": "Network activity",
        "value": "circl.lu",
        "timestamp": "1603642920",
        "comment": "Hostname test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Hostname test attribute",
          "pattern": "[domain-name:value = 'circl.lu']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"hostname\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              }
          },
          "labels": [
              "misp:type=\"hostname\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              }
          },
          "labels": [
              "misp:type=\"hostname\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- hostname|port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "hostname|port",
        "category": "Network activity",
        "value": "circl.lu|8443",
        "timestamp": "1603642920",
        "comment": "Hostname|port test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Hostname|port test attribute",
          "pattern": "[domain-name:value = 'circl.lu' AND network-traffic:dst_port = '8443']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"hostname|port\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              },
              "1": {
                  "type": "network-traffic",
                  "dst_ref": "0",
                  "dst_port": 8443,
                  "protocols": [
                      "tcp"
                  ]
              }
          },
          "labels": [
              "misp:type=\"hostname|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "domain-name",
                  "value": "circl.lu"
              },
              "1": {
                  "type": "network-traffic",
                  "dst_ref": "0",
                  "dst_port": 8443,
                  "protocols": [
                      "tcp"
                  ]
              }
          },
          "labels": [
              "misp:type=\"hostname|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- http-method
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "http-method",
        "category": "Network activity",
        "value": "POST",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[network-traffic:extensions.'http-request-ext'.request_method = 'POST']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"http-method\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```

- ip-dst
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "ip-dst",
        "category": "Network activity",
        "value": "5.6.7.8",
        "timestamp": "1603642920",
        "comment": "Destination IP test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Destination IP test attribute",
          "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"ip-dst\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "dst_ref": "1",
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:type=\"ip-dst\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "dst_ref": "1",
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:type=\"ip-dst\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- ip-dst|port
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "ip-dst|port",
        "category": "Network activity",
        "value": "5.6.7.8|5678",
        "timestamp": "1603642920",
        "comment": "Destination IP | Port test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Destination IP | Port test attribute",
          "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8' AND network-traffic:dst_port = '5678']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"ip-dst|port\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "dst_ref": "1",
                  "dst_port": 5678,
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:type=\"ip-dst|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "network-traffic",
                  "dst_ref": "1",
                  "dst_port": 5678,
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "5.6.7.8"
              }
          },
          "labels": [
              "misp:type=\"ip-dst|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- ip-src
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "ip-src",
        "category": "Network activity",
        "value": "1.2.3.4",
        "timestamp": "1603642920",
        "comment": "Source IP test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Source IP test attribute",
          "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"ip-src\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              }
          },
          "labels": [
              "misp:type=\"ip-src\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              }
          },
          "labels": [
              "misp:type=\"ip-src\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- ip-src|port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "ip-src|port",
        "category": "Network activity",
        "value": "1.2.3.4|1234",
        "timestamp": "1603642920",
        "comment": "Source IP | Port test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Source IP | Port test attribute",
          "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4' AND network-traffic:src_port = '1234']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"ip-src|port\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                  "src_port": 1234,
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              }
          },
          "labels": [
              "misp:type=\"ip-src|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                  "src_port": 1234,
                  "protocols": [
                      "tcp"
                  ]
              },
              "1": {
                  "type": "ipv4-addr",
                  "value": "1.2.3.4"
              }
          },
          "labels": [
              "misp:type=\"ip-src|port\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- link
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "link",
        "category": "Network activity",
        "value": "https://github.com/MISP/MISP",
        "timestamp": "1603642920",
        "comment": "Link test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Link test attribute",
          "pattern": "[url:value = 'https://github.com/MISP/MISP']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"link\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "url",
                  "value": "https://github.com/MISP/MISP"
              }
          },
          "labels": [
              "misp:type=\"link\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- mac-address
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "mac-address",
        "category": "Payload delivery",
        "value": "12:34:56:78:90:AB",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[mac-addr:value = '12:34:56:78:90:AB']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"mac-address\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "mac-addr",
                  "value": "12:34:56:78:90:ab"
              }
          },
          "labels": [
              "misp:type=\"mac-address\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "mac-addr",
                  "value": "12:34:56:78:90:ab"
              }
          },
          "labels": [
              "misp:type=\"mac-address\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- malware-sample
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "malware-sample",
        "category": "Payload delivery",
        "value": "oui|8764605c6f388c89096b534d33565802",
        "data": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==",
        "timestamp": "1603642920",
        "comment": "Malware Sample test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Malware Sample test attribute",
          "pattern": "[file:name = 'oui' AND file:hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:content_ref.payload_bin = 'UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA==' AND file:content_ref.mime_type = 'application/zip']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"malware-sample\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "8764605c6f388c89096b534d33565802"
                  },
                  "name": "oui",
                  "content_ref": "1"
              },
              "1": {
                  "type": "artifact",
                  "mime_type": "application/zip",
                  "payload_bin": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA=="
              }
          },
          "labels": [
              "misp:type=\"malware-sample\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "8764605c6f388c89096b534d33565802"
                  },
                  "name": "oui",
                  "content_ref": "1"
              },
              "1": {
                  "type": "artifact",
                  "mime_type": "application/zip",
                  "payload_bin": "UEsDBAoACQAAAAaOU1EvUbi[...]AACAAIA2QAAAB8BAAAAAA=="
              }
          },
          "labels": [
              "misp:type=\"malware-sample\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "md5",
        "category": "Payload delivery",
        "value": "b2a5abfeef9e36964281a31e17b57c97",
        "timestamp": "1603642920",
        "comment": "MD5 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "MD5 test attribute",
          "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"md5\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                  }
              }
          },
          "labels": [
              "misp:type=\"md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                  }
              }
          },
          "labels": [
              "misp:type=\"md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- mutex
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "mutex",
        "category": "Artifacts dropped",
        "value": "MutexTest",
        "timestamp": "1603642920",
        "comment": "Mutex test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Mutex test attribute",
          "pattern": "[mutex:name = 'MutexTest']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Artifacts dropped"
              }
          ],
          "labels": [
              "misp:type=\"mutex\"",
              "misp:category=\"Artifacts dropped\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "mutex",
                  "name": "MutexTest"
              }
          },
          "labels": [
              "misp:type=\"mutex\"",
              "misp:category=\"Artifacts dropped\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "mutex",
                  "name": "MutexTest"
              }
          },
          "labels": [
              "misp:type=\"mutex\"",
              "misp:category=\"Artifacts dropped\""
          ]
      }
      ```

- port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "port",
        "category": "Network activity",
        "value": "8443",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[network-traffic:dst_port = '8443']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"port\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```

- regkey
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "regkey",
        "category": "Persistence mechanism",
        "value": "HKLM\\Software\\mthjk",
        "timestamp": "1603642920",
        "comment": "Regkey test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Regkey test attribute",
          "pattern": "[windows-registry-key:key = 'HKLM\\\\Software\\\\mthjk']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Persistence mechanism"
              }
          ],
          "labels": [
              "misp:type=\"regkey\"",
              "misp:category=\"Persistence mechanism\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "HKLM\\Software\\mthjk"
              }
          },
          "labels": [
              "misp:type=\"regkey\"",
              "misp:category=\"Persistence mechanism\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "HKLM\\Software\\mthjk"
              }
          },
          "labels": [
              "misp:type=\"regkey\"",
              "misp:category=\"Persistence mechanism\""
          ]
      }
      ```

- regkey|value
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "regkey|value",
        "category": "Persistence mechanism",
        "value": "HKLM\\Software\\mthjk|%DATA%\\1234567890",
        "timestamp": "1603642920",
        "comment": "Regkey | value test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "Regkey | value test attribute",
          "pattern": "[windows-registry-key:key = 'HKLM\\\\Software\\\\mthjk' AND windows-registry-key:values.data = '\\\\%DATA\\\\%\\\\1234567890']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Persistence mechanism"
              }
          ],
          "labels": [
              "misp:type=\"regkey|value\"",
              "misp:category=\"Persistence mechanism\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "HKLM\\Software\\mthjk",
                  "values": [
                      {
                          "name": "",
                          "data": "%DATA%\\1234567890"
                      }
                  ]
              }
          },
          "labels": [
              "misp:type=\"regkey|value\"",
              "misp:category=\"Persistence mechanism\""
          ]
      }
      ```
    - Obsevred_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "HKLM\\Software\\mthjk",
                  "values": [
                      {
                          "name": "",
                          "data": "%DATA%\\1234567890"
                      }
                  ]
              }
          },
          "labels": [
              "misp:type=\"regkey|value\"",
              "misp:category=\"Persistence mechanism\""
          ]
      }
      ```
    - Obsevred Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "windows-registry-key",
                  "key": "HKLM\\Software\\mthjk",
                  "values": [
                      {
                          "name": "",
                          "data": "%DATA%\\1234567890"
                      }
                  ]
              }
          },
          "labels": [
              "misp:type=\"regkey|value\"",
              "misp:category=\"Persistence mechanism\""
          ]
      }
      ```

- sha1
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "sha1",
        "category": "Payload delivery",
        "value": "2920d5e6c579fce772e5506caf03af65579088bd",
        "timestamp": "1603642920",
        "comment": "SHA1 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA1 test attribute",
          "pattern": "[file:hashes.SHA1 = '2920d5e6c579fce772e5506caf03af65579088bd']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha1\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
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
                      "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
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
                      "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha224
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "sha224",
        "category": "Payload delivery",
        "value": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9",
        "timestamp": "1603642920",
        "comment": "SHA224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA224 test attribute",
          "pattern": "[file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
                      "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
                      "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha256",
        "category": "Payload delivery",
        "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "SHA256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA256 test attribute",
          "pattern": "[file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha3-224
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "sha3-224",
        "category": "Payload delivery",
        "value": "3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618",
        "timestamp": "1603642920",
        "comment": "SHA3-224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA3-224 test attribute",
          "pattern": "[file:hashes.SHA3224 = '3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha3-224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-224": "3bd6507ef58d2fecb14d39bfffbee5c71dcf7930191cc2df2e507618"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha3-224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha3-256
  - MISP
    ```json
    {
        "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "type": "sha3-256",
        "category": "Payload delivery",
        "value": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4",
        "timestamp": "1603642920",
        "comment": "SHA3-256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA3-256 test attribute",
          "pattern": "[file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha3-256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
                      "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha3-256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
                      "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha3-256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha3-384
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "sha3-384",
        "category": "Payload delivery",
        "value": "93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568",
        "timestamp": "1603642920",
        "comment": "SHA3-384 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA3-384 test attribute",
          "pattern": "[file:hashes.SHA3384 = '93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha3-384\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-384": "93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha3-384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha3-512
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "sha3-512",
        "category": "Payload delivery",
        "value": "fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748",
        "timestamp": "1603642920",
        "comment": "SHA3-512 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA3-512 test attribute",
          "pattern": "[file:hashes.SHA3512 = 'fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha3-512\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA3-512": "fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha3-512\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha384
  - MISP
    ```json
    {
        "uuid": "90bd7dae-b78c-4025-9073-568950c780fb",
        "type": "sha384",
        "category": "Payload delivery",
        "value": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce",
        "timestamp": "1603642920",
        "comment": "SHA384 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA384 test attribute",
          "pattern": "[file:hashes.SHA384 = 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha384\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
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
                      "SHA-384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
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
                      "SHA-384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha384\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha512
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha512",
        "category": "Payload delivery",
        "value": "06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5",
        "timestamp": "1603642920",
        "comment": "SHA512 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA512 test attribute",
          "pattern": "[file:hashes.SHA512 = '06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha512\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-512": "06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha512\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha512/224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha512/224",
        "category": "Payload delivery",
        "value": "2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc",
        "timestamp": "1603642920",
        "comment": "SHA512/224 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA512/224 test attribute",
          "pattern": "[file:hashes.SHA224 = '2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha512/224\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
                      "SHA-224": "2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha512/224\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- sha512/256
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "sha512/256",
        "category": "Payload delivery",
        "value": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93",
        "timestamp": "1603642920",
        "comment": "SHA512/256 test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SHA512/256 test attribute",
          "pattern": "[file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"sha512/256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha512/256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
                      "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                  }
              }
          },
          "labels": [
              "misp:type=\"sha512/256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- size-in-bytes
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "size-in-bytes",
        "value": "1234",
        "category": "Other",
        "timestamp": "1603642920"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "pattern": "[file:size = '1234']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Other"
              }
          ],
          "labels": [
              "misp:type=\"size-in-bytes\"",
              "misp:category=\"Other\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```

- ssdeep
  - MISP
    ```json
    {
        "uuid": "2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "type": "ssdeep",
        "category": "Payload delivery",
        "value": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi",
        "timestamp": "1603642920",
        "comment": "SSDEEP test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "SSDEEP test attribute",
          "pattern": "[file:hashes.SSDEEP = '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"ssdeep\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
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
                      "ssdeep": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
                  }
              }
          },
          "labels": [
              "misp:type=\"ssdeep\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
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
                      "ssdeep": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
                  }
              }
          },
          "labels": [
              "misp:type=\"ssdeep\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- tlsh
  - MISP
    ```json
    {
        "uuid": "2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "type": "tlsh",
        "category": "Payload delivery",
        "value": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297",
        "timestamp": "1603642920",
        "comment": "TLSH test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "TLSH test attribute",
          "pattern": "[file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"tlsh\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
                      "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
                  }
              }
          },
          "labels": [
              "misp:type=\"tlsh\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
                      "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
                  }
              }
          },
          "labels": [
              "misp:type=\"tlsh\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- uri
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "uri",
        "category": "Network activity",
        "value": "http://176.58.32.109/upd/51",
        "timestamp": "1603642920",
        "comment": "URI test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "URI test attribute",
          "pattern": "[url:value = 'http://176.58.32.109/upd/51']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"uri\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "url",
                  "value": "http://176.58.32.109/upd/51"
              }
          },
          "labels": [
              "misp:type=\"uri\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- url
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "url",
        "category": "Network activity",
        "value": "https://misp-project.org/download/",
        "timestamp": "1603642920",
        "comment": "URL test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "URL test attribute",
          "pattern": "[url:value = 'https://misp-project.org/download/']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"url\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "url",
                  "value": "https://misp-project.org/download/"
              }
          },
          "labels": [
              "misp:type=\"url\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "url",
                  "value": "https://misp-project.org/download/"
              }
          },
          "labels": [
              "misp:type=\"url\"",
              "misp:category=\"Network activity\""
          ]
      }
      ```

- user-agent
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "user-agent",
        "category": "Network activity",
        "value": "Mozilla Firefox",
        "timestamp": "1603642920",
        "comment": "User-agent test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "User-agent test attribute",
          "pattern": "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'Mozilla Firefox']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Network activity"
              }
          ],
          "labels": [
              "misp:type=\"user-agent\"",
              "misp:category=\"Network activity\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```

- vulnerability
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "vulnerability",
        "category": "External analysis",
        "value": "CVE-2017-11774",
        "timestamp": "1603642920",
        "comment": "Vulnerability test attribute"
    }
    ```
  - STIX
    - Vulnerability
      ```json
      {
          "type": "vulnerability",
          "id": "vulnerability--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "name": "CVE-2017-11774",
          "labels": [
              "misp:type=\"vulnerability\"",
              "misp:category=\"External analysis\"",
              "misp:to_ids=\"True\""
          ],
          "external_references": [
              {
                  "source_name": "cve",
                  "external_id": "CVE-2017-11774"
              }
          ]
      }
      ```

- x509-fingerprint-md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "x509-fingerprint-md5",
        "category": "Payload delivery",
        "value": "8764605c6f388c89096b534d33565802",
        "timestamp": "1603642920",
        "comment": "X509 MD5 fingerprint test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "X509 MD5 fingerprint test attribute",
          "pattern": "[x509-certificate:hashes.MD5 = '8764605c6f388c89096b534d33565802']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"x509-fingerprint-md5\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "MD5": "8764605c6f388c89096b534d33565802"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "MD5": "8764605c6f388c89096b534d33565802"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-md5\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- x509-fingerprint-sha1
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "x509-fingerprint-sha1",
        "category": "Payload delivery",
        "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
        "timestamp": "1603642920",
        "comment": "X509 SHA1 fingerprint test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "X509 SHA1 fingerprint test attribute",
          "pattern": "[x509-certificate:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"x509-fingerprint-sha1\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-sha1\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```

- x509-fingerprint-sha256
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "x509-fingerprint-sha256",
        "category": "Payload delivery",
        "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "X509 SHA256 fingerprint test attribute"
    }
    ```
  - STIX
    - Indicator
      ```json
      {
          "type": "indicator",
          "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "description": "X509 SHA256 fingerprint test attribute",
          "pattern": "[x509-certificate:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b']",
          "valid_from": "2020-10-25T16:22:00Z",
          "kill_chain_phases": [
              {
                  "kill_chain_name": "misp-category",
                  "phase_name": "Payload delivery"
              }
          ],
          "labels": [
              "misp:type=\"x509-fingerprint-sha256\"",
              "misp:category=\"Payload delivery\"",
              "misp:to_ids=\"True\""
          ]
      }
      ```
    - Observed Data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-sha256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```
    - Observed_data
      ```json
      {
          "type": "observed-data",
          "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
          "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
          "created": "2020-10-25T16:22:00.000Z",
          "modified": "2020-10-25T16:22:00.000Z",
          "first_observed": "2020-10-25T16:22:00Z",
          "last_observed": "2020-10-25T16:22:00Z",
          "number_observed": 1,
          "objects": {
              "0": {
                  "type": "x509-certificate",
                  "hashes": {
                      "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
                  }
              }
          },
          "labels": [
              "misp:type=\"x509-fingerprint-sha256\"",
              "misp:category=\"Payload delivery\""
          ]
      }
      ```


### Unmapped attribute types

You may have noticed we are very far from having all the attribute types supported. This is due to the various use cases that MISP can be used for.  
Nonetheless, every attribute whose type is not in the list, is exported as `Custom` object.  
With the following examples, `btc` and `iban` are attribute types that are not mapped, where the other ones:
- are already mentioned above and giving valid STIX 2.0 pattern expressions when their `to_ids` flag is set to `True`.
- are not providing enough information to produce Observable objects and are then exported as `Custom` objects when their `to_ids` flag is unset.

Let us see those examples of custom objects exported from attributes:
- btc
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "btc",
        "category": "Financial fraud",
        "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
        "timestamp": "1603642920",
        "comment": "Btc test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-btc",
        "id": "x-misp-object-btc--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"btc\"",
            "misp:category=\"Financial fraud\"",
            "misp:to_ids=\"True\""
        ],
        "x_misp_category": "Financial fraud",
        "x_misp_comment": "Btc test attribute",
        "x_misp_value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE"
    }
    ```

- http-method
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "http-method",
        "category": "Network activity",
        "value": "POST",
        "timestamp": "1603642920",
        "to_ids": false
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-http-method",
        "id": "x-misp-object-http-method--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"http-method\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_value": "POST"
    }
    ```

- iban
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "iban",
        "category": "Financial fraud",
        "value": "LU1234567890ABCDEF1234567890",
        "timestamp": "1603642920",
        "comment": "IBAN test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-iban",
        "id": "x-misp-object-iban--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"iban\"",
            "misp:category=\"Financial fraud\"",
            "misp:to_ids=\"True\""
        ],
        "x_misp_category": "Financial fraud",
        "x_misp_comment": "IBAN test attribute",
        "x_misp_value": "LU1234567890ABCDEF1234567890"
    }
    ```

- port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "port",
        "category": "Network activity",
        "value": "8443",
        "timestamp": "1603642920",
        "to_ids": false
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-port",
        "id": "x-misp-object-port--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"port\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_value": "8443"
    }
    ```

- size-in-bytes
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "size-in-bytes",
        "value": "1234",
        "category": "Other",
        "timestamp": "1603642920",
        "to_ids": false
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-size-in-bytes",
        "id": "x-misp-object-size-in-bytes--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"size-in-bytes\"",
            "misp:category=\"Other\""
        ],
        "x_misp_category": "Other",
        "x_misp_value": "1234"
    }
    ```

- user-agent
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "user-agent",
        "category": "Network activity",
        "value": "Mozilla Firefox",
        "timestamp": "1603642920",
        "comment": "User-agent test attribute",
        "to_ids": false
    }
    ```
  - STIX
    ```json
    {
        "type": "x-misp-object-user-agent",
        "id": "x-misp-object-user-agent--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2021-03-11T13:40:59.000Z",
        "modified": "2021-03-11T13:40:59.000Z",
        "labels": [
            "misp:type=\"user-agent\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_comment": "User-agent test attribute",
        "x_misp_value": "Mozilla Firefox"
    }
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX 2.0 mapping](misp_events_to_stix20.md)
- [Objects export to STIX 2.0 mapping](misp_objects_to_stix20.md)
- [Galaxies export to STIX 2.0 mapping](misp_galaxies_to_stix20.md)

([Go back to the main documentation](README.md))
