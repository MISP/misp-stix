# External STIX 2.0 to MISP Objects mapping

MISP Objects are containers grouping related MISP attributes. When importing external STIX 2.0 content (bundles not produced by MISP), composite STIX structures (an `Indicator` with a multi-field pattern, or an `Observed Data` with multiple observable objects) are mapped to the corresponding MISP object template. In addition, a standalone `Identity` SDO is mapped directly to an `identity` (or `organization`) MISP object.

The list of currently supported MISP object templates is available [here](https://github.com/MISP/misp-objects).

### Current mapping

- artifact
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive malicious artifact indicator",
        "description": "Artifact indicator covering mime_type, payload_bin, hashes, and decryption_key.",
        "pattern": "[artifact:mime_type = 'application/zip' AND artifact:payload_bin = 'UEsDBAoACQAAAKBINlgCq9F[...]AAAAQABAEkAAABdAAAAAAA=' AND artifact:hashes.MD5 = 'bc590af5f7b16b890860248dc0d4c68f' AND artifact:hashes.'SHA-1' = '003d59659a3e28781aaf03da1ac1cb0e326ed65e' AND artifact:hashes.'SHA-256' = '2dd39c08867f34010fd9ea1833aa549a02da16950dda4a8ef922113a9eccd963']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "artifact",
        "meta-category": "file",
        "template_uuid": "0a46df3a-bd9b-472c-a1e7-6aede7094483",
        "description": "The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload. From STIX 2.1 (6.1)",
        "template_version": "3",
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "Attribute": [
            {
                "uuid": "b207c9bb-4fff-5971-94c9-df5592d45b85",
                "object_relation": "mime_type",
                "value": "application/zip",
                "type": "mime-type",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Artifacts dropped"
            },
            {
                "data": "UEsDBAoACQAAAKBINlgCq9F[...]AAAAQABAEkAAABdAAAAAAA=",
                "uuid": "dbd1833c-33cd-5fbd-bcd1-65760f954f3a",
                "object_relation": "payload_bin",
                "value": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "type": "attachment",
                "disable_correlation": false,
                "to_ids": true,
                "category": "External analysis"
            },
            {
                "uuid": "e69b2ece-5c62-5d4a-bc31-8b688e5fed9b",
                "object_relation": "md5",
                "value": "bc590af5f7b16b890860248dc0d4c68f",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            },
            {
                "uuid": "1cce8e84-0a6e-5879-9e7d-87b3df7258a9",
                "object_relation": "sha1",
                "value": "003d59659a3e28781aaf03da1ac1cb0e326ed65e",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            },
            {
                "uuid": "55a2d975-c380-5e65-8d5b-b7a384b095d1",
                "object_relation": "sha256",
                "value": "2dd39c08867f34010fd9ea1833aa549a02da16950dda4a8ef922113a9eccd963",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "artifact",
                "mime_type": "application/zip",
                "payload_bin": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
                "hashes": {
                    "MD5": "5bfd0814254d0ff993a83560cb740042",
                    "SHA-1": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                    "SHA-256": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa"
                },
                "decryption_key": "clear"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "artifact",
        "meta-category": "file",
        "template_uuid": "0a46df3a-bd9b-472c-a1e7-6aede7094483",
        "description": "The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload. From STIX 2.1 (6.1)",
        "template_version": "3",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "data": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
                "uuid": "f16401a5-b0c4-5b71-adfc-219b0c2f598e",
                "object_relation": "payload_bin",
                "value": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
                "type": "attachment",
                "disable_correlation": false,
                "to_ids": false,
                "category": "External analysis"
            },
            {
                "uuid": "44282519-e58d-5f03-ac6b-67a9b65df34e",
                "object_relation": "md5",
                "value": "5bfd0814254d0ff993a83560cb740042",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "d9aea0eb-d4df-5a16-b3ca-a5b12ed1405b",
                "object_relation": "sha1",
                "value": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "2bb97f4b-1ba9-5cdf-8557-1bdf456384fa",
                "object_relation": "sha256",
                "value": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "6e502884-330e-5598-a877-43c94af90ecb",
                "object_relation": "decryption_key",
                "value": "clear",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "6aabb998-7924-5859-98f9-e56861063bd3",
                "object_relation": "mime_type",
                "value": "application/zip",
                "type": "mime-type",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Artifacts dropped"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- asn
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive autonomous system indicator",
        "description": "Autonomous system indicator covering number and name fields.",
        "pattern": "[autonomous-system:number = 197869 AND autonomous-system:name = 'CIRCL']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "asn",
        "meta-category": "network",
        "template_uuid": "4ec55cc6-9e49-4c64-b794-03c25c1a6587",
        "description": "Autonomous system object describing an autonomous system which can include one or more network operators managing an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.",
        "template_version": "6",
        "uuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "Attribute": [
            {
                "uuid": "4a35e1f6-4ab9-57ee-baf4-382c4fe3b92a",
                "object_relation": "asn",
                "value": "AS197869",
                "type": "AS",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "ae528477-d1e4-5658-8f27-eae3ffe3d6e5",
                "object_relation": "description",
                "value": "CIRCL",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "autonomous-system",
                "number": 197869,
                "name": "CIRCL"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "asn",
        "meta-category": "network",
        "template_uuid": "4ec55cc6-9e49-4c64-b794-03c25c1a6587",
        "description": "Autonomous system object describing an autonomous system which can include one or more network operators managing an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.",
        "template_version": "6",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "a3cb6626-8291-5f43-aaa7-f530ba4491c8",
                "object_relation": "asn",
                "value": "AS197869",
                "type": "AS",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "5d4a3a5c-a169-5f7d-8c24-478265ec08b6",
                "object_relation": "description",
                "value": "CIRCL",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- directory
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive directory indicator",
        "description": "Directory indicator covering path, path_enc, created, modified, and accessed.",
        "pattern": "[directory:path = '/var/www/MISP' AND directory:path_enc = 'UTF-8' AND directory:created = '2011-11-26T10:45:31Z' AND directory:modified = '2023-12-12T11:34:05Z' AND directory:accessed = '2023-12-12T11:34:05Z']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "directory",
        "meta-category": "file",
        "template_uuid": "23ac6a02-1017-4ea6-a4df-148ed563988d",
        "description": "Directory object describing a directory with meta-information",
        "template_version": "1",
        "uuid": "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
        "Attribute": [
            {
                "uuid": "62149228-6465-56e6-b43a-a5041f1995dc",
                "object_relation": "path",
                "value": "/var/www/MISP",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "1aaf580a-1cb4-54d3-8329-c9d1700c7fda",
                "object_relation": "path-encoding",
                "value": "UTF-8",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "00c628d6-35d8-5476-aba5-7da8d945a019",
                "object_relation": "creation-time",
                "value": "2011-11-26T10:45:31+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "c2db0243-13f2-5526-b37e-e2ae854d580a",
                "object_relation": "modification-time",
                "value": "2023-12-12T11:34:05+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "36c73cd4-268c-546c-a979-065f1ad59750",
                "object_relation": "access-time",
                "value": "2023-12-12T11:34:05+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "directory",
                "path": "/var/www/MISP/app/files/scripts/misp-stix",
                "path_enc": "ISO-8859-1",
                "created": "2021-07-21T11:44:56Z",
                "modified": "2023-12-12T11:24:30Z",
                "accessed": "2023-12-12T11:24:30Z"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "directory",
        "meta-category": "file",
        "template_uuid": "23ac6a02-1017-4ea6-a4df-148ed563988d",
        "description": "Directory object describing a directory with meta-information",
        "template_version": "1",
        "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
        "Attribute": [
            {
                "uuid": "6a6f0709-fbc6-52db-8bd9-b3351ed07372",
                "object_relation": "access-time",
                "value": "2023-12-12T11:24:30+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "487c531c-a957-5127-9ba4-703ddc07be7e",
                "object_relation": "creation-time",
                "value": "2021-07-21T11:44:56+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e73c3f00-b958-5838-9a17-dd231fe79686",
                "object_relation": "modification-time",
                "value": "2023-12-12T11:24:30+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "58bea47f-96f4-5136-acfb-5c35364f522f",
                "object_relation": "path",
                "value": "/var/www/MISP/app/files/scripts/misp-stix",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e85b779e-86a0-5599-ab1f-d2f0d84297d3",
                "object_relation": "path-encoding",
                "value": "ISO-8859-1",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- domain-ip
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--d4e1caeb-f5d3-47a7-ac54-5320d2bd706e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Domain with suspicious IP resolution",
        "description": "Domain resolving to a suspicious IP address.",
        "pattern": "[domain-name:value = 'example.com' AND domain-name:resolves_to_refs[*].value = '198.51.100.3']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "domain-ip",
        "meta-category": "network",
        "template_uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734",
        "description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
        "template_version": "11",
        "uuid": "d4e1caeb-f5d3-47a7-ac54-5320d2bd706e",
        "Attribute": [
            {
                "uuid": "f95b8bc6-7a4d-59e9-9096-3d7fd768ff42",
                "object_relation": "domain",
                "value": "example.com",
                "type": "domain",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "b185b3f9-9ae8-5d0c-bbc9-31c8750bc818",
                "object_relation": "ip",
                "value": "198.51.100.3",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "domain-name",
                "value": "example.com",
                "resolves_to_refs": [
                    "1",
                    "2"
                ]
            },
            "1": {
                "type": "ipv4-addr",
                "value": "198.51.100.3"
            },
            "2": {
                "type": "ipv6-addr",
                "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            },
            "3": {
                "type": "domain-name",
                "value": "blog.example.com",
                "resolves_to_refs": [
                    "0"
                ]
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "domain-ip",
        "meta-category": "network",
        "template_uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734",
        "description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
        "template_version": "11",
        "uuid": "5cfbdc1b-1240-57eb-b6e8-d6fe7349221a",
        "Attribute": [
            {
                "uuid": "263da550-3a00-5265-a2bd-8d467c85ec6d",
                "object_relation": "domain",
                "value": "example.com",
                "type": "domain",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "3e399d23-87b6-587d-a08a-a3a4aa0e0594",
                "object_relation": "ip",
                "value": "198.51.100.3",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "906f097a-0ba5-5c65-8e3f-e547075c3bf3",
                "object_relation": "ip",
                "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1606321320",
        "first_seen": "2020-10-25T16:22:00+00:00",
        "last_seen": "2020-11-25T16:22:00+00:00",
        "comment": "Observed Data ID: observed-data--3cd23a7b-a099-49df-b397-189018311d4e"
    }
    ```

- email
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive email message indicator",
        "description": "Email message indicator covering multipart, content_type, date, subject, from/to/cc refs, headers, and body.",
        "pattern": "[email-message:date = '2016-06-19T14:20:40.000Z' AND email-message:subject = 'Check out this picture of a cat!' AND email-message:from_ref.value = 'jdoe@example.com' AND email-message:to_refs[*].value = 'bob@example.com' AND email-message:cc_refs[*].value = 'mary@example.com' AND email-message:additional_header_fields.'X-Mailer' = 'Mutt/1.5.23' AND email-message:body_multipart[0].content_type = 'text/plain; charset=utf-8' AND email-message:body_multipart[0].body = 'Cats are funny!']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "email",
        "meta-category": "network",
        "template_uuid": "a0c666e0-fc65-4be8-b48f-3423d788b552",
        "description": "Email object describing an email with meta-information",
        "template_version": "19",
        "uuid": "d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80",
        "Attribute": [
            {
                "uuid": "cbc27b96-1850-54a4-a3c5-364a8651ce5e",
                "object_relation": "send-date",
                "value": "2016-06-19T14:20:40+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": true,
                "to_ids": true
            },
            {
                "uuid": "b1974c51-6e2c-590a-bf6d-6e6c85654c9a",
                "object_relation": "subject",
                "value": "Check out this picture of a cat!",
                "type": "email-subject",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "5fa0c069-e9ad-59a5-a2b6-d121394faa31",
                "object_relation": "from",
                "value": "jdoe@example.com",
                "type": "email-src",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "bf1377e7-1d93-55a7-a6d1-f8c597be19ea",
                "object_relation": "to",
                "value": "bob@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": true
            },
            {
                "uuid": "a07d9c92-3615-5373-8126-45f58b836780",
                "object_relation": "cc",
                "value": "mary@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": true
            },
            {
                "uuid": "619184c2-44a0-5b60-9973-8d794efcbafe",
                "object_relation": "x-mailer",
                "value": "Mutt/1.5.23",
                "type": "email-x-mailer",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": true
            },
            {
                "uuid": "44c13432-43dc-5b17-adc3-233a1109666a",
                "object_relation": "email-body",
                "value": "Cats are funny!",
                "type": "email-body",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": true
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-message",
                "is_multipart": true,
                "date": "2016-06-19T14:20:40Z",
                "content_type": "multipart/mixed",
                "from_ref": "1",
                "to_refs": [
                    "2"
                ],
                "cc_refs": [
                    "3"
                ],
                "subject": "Check out this picture of a cat!",
                "received_lines": [
                    "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)"
                ],
                "additional_header_fields": {
                    "Content-Disposition": "inline",
                    "X-Mailer": "Mutt/1.5.23",
                    "X-Originating-IP": "198.51.100.3"
                },
                "body_multipart": [
                    {
                        "body": "Cats are funny!",
                        "content_type": "text/plain; charset=utf-8",
                        "content_disposition": "inline"
                    },
                    {
                        "body_raw_ref": "4",
                        "content_type": "image/png",
                        "content_disposition": "attachment; filename=\"tabby.png\""
                    },
                    {
                        "body_raw_ref": "5",
                        "content_type": "application/zip",
                        "content_disposition": "attachment; filename=\"tabby_pics.zip\""
                    }
                ]
            },
            "1": {
                "type": "email-addr",
                "value": "jdoe@example.com",
                "display_name": "John Doe"
            },
            "2": {
                "type": "email-addr",
                "value": "bob@example.com",
                "display_name": "Bob Smith"
            },
            "3": {
                "type": "email-addr",
                "value": "mary@example.com",
                "display_name": "Mary Smith"
            },
            "4": {
                "type": "artifact",
                "mime_type": "image/jpeg",
                "payload_bin": "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",
                "hashes": {
                    "SHA-256": "effb46bba03f6c8aea5c653f9cf984f170dcdd3bbbe2ff6843c3e5da0e698766"
                }
            },
            "5": {
                "type": "file",
                "hashes": {
                    "SHA-256": "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db"
                },
                "name": "tabby_pics.zip",
                "magic_number_hex": "504B0304"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "email",
        "meta-category": "network",
        "template_uuid": "a0c666e0-fc65-4be8-b48f-3423d788b552",
        "description": "Email object describing an email with meta-information",
        "template_version": "19",
        "uuid": "5cfbdc1b-1240-57eb-b6e8-d6fe7349221a",
        "ObjectReference": [
            {
                "uuid": "4413044b-e0ed-54e4-8aa0-a48292fa97a0",
                "object_uuid": "5cfbdc1b-1240-57eb-b6e8-d6fe7349221a",
                "referenced_uuid": "1ae2c084-4e23-52b5-935b-c3404778fa88",
                "relationship_type": "contains"
            },
            {
                "uuid": "164fa9fb-f0d4-5ae8-887d-0ee1646576dd",
                "object_uuid": "5cfbdc1b-1240-57eb-b6e8-d6fe7349221a",
                "referenced_uuid": "e47e1009-9864-5bd4-97cc-e13b1bf7c3bf",
                "relationship_type": "contains"
            }
        ],
        "Attribute": [
            {
                "uuid": "caad5ead-0387-5295-a29f-583216914a5d",
                "object_relation": "send-date",
                "value": "2016-06-19T14:20:40+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "b524417e-5ec8-5e47-9042-9c45ea9925f0",
                "object_relation": "header",
                "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)",
                "type": "email-header",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "bfaa0f9d-a403-5e90-be7b-635e88ea5f05",
                "object_relation": "subject",
                "value": "Check out this picture of a cat!",
                "type": "email-subject",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "843e0b2a-8491-5b03-be56-8d618a6201dd",
                "object_relation": "x-mailer",
                "value": "Mutt/1.5.23",
                "type": "email-x-mailer",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "ead56b1a-b661-58a5-8665-b83277bf0cdc",
                "object_relation": "received-header-ip",
                "value": "198.51.100.3",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "acdad81f-9ceb-5f81-bc32-60aa4a648a97",
                "object_relation": "from",
                "value": "jdoe@example.com",
                "type": "email-src",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "3151a4ad-44d4-596c-9383-87acf26afd06",
                "object_relation": "from-display-name",
                "value": "John Doe",
                "type": "email-src-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "70a4c3f1-7b3d-58ad-94c6-c640fc8df2e5",
                "object_relation": "to",
                "value": "bob@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "defebddc-ee13-595e-86dd-cd60878d0bf3",
                "object_relation": "to-display-name",
                "value": "Bob Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "24ffdfa9-fec8-504f-9c93-b22165432564",
                "object_relation": "cc",
                "value": "mary@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "7cd65d66-d1a0-515f-85ff-b0b90595f0b1",
                "object_relation": "cc-display-name",
                "value": "Mary Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "c308a5df-5fca-53a3-9a85-cab9c493afda",
                "object_relation": "email-body",
                "value": "Cats are funny!",
                "type": "email-body",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1606321320",
        "first_seen": "2020-10-25T16:22:00+00:00",
        "last_seen": "2020-11-25T16:22:00+00:00",
        "comment": "Observed Data ID: observed-data--3cd23a7b-a099-49df-b397-189018311d4e"
    }
    ```

- file
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive file indicator",
        "pattern": "[file:hashes.'MD5' = '8764605c6f388c89096b534d33565802' AND file:hashes.'SHA-1' = '46aba99aa7158e4609aaa72b50990842fd22ae86' AND file:hashes.'SHA-256' = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b' AND file:size = 35 AND file:name = 'oui' AND file:name_enc = 'UTF-8']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "file",
        "meta-category": "file",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "template_version": "25",
        "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
        "Attribute": [
            {
                "uuid": "b35e4661-524c-5f93-b50c-9b06d8771ecd",
                "object_relation": "md5",
                "value": "8764605c6f388c89096b534d33565802",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            },
            {
                "uuid": "3658f8d6-a658-5bf7-a5c3-7f96ac89fc65",
                "object_relation": "sha1",
                "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            },
            {
                "uuid": "913515d1-4580-5b19-93aa-5b66c54c6e23",
                "object_relation": "sha256",
                "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Payload delivery"
            },
            {
                "uuid": "cc05c743-7a13-5385-87b5-e8462122882b",
                "object_relation": "size-in-bytes",
                "value": "35",
                "type": "size-in-bytes",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "ec60937d-4962-57a7-ba8e-5eed49a4da82",
                "object_relation": "filename",
                "value": "oui",
                "type": "filename",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": true
            },
            {
                "uuid": "d386bb36-fa15-5b93-b290-0bc27ff1c796",
                "object_relation": "file-encoding",
                "value": "UTF-8",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a",
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
                "mime_type": "application/zip",
                "payload_bin": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
                "hashes": {
                    "MD5": "8764605c6f388c89096b534d33565802"
                },
                "decryption_key": "infected",
                "encryption_algorithm": "mime-type-indicated"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "file",
        "meta-category": "file",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "template_version": "25",
        "uuid": "7280bbbc-b266-5dea-af4d-ebe1499edc50",
        "ObjectReference": [
            {
                "uuid": "63fdfe41-6f81-5019-9b37-7cd81e21e4b5",
                "object_uuid": "7280bbbc-b266-5dea-af4d-ebe1499edc50",
                "referenced_uuid": "d30b62a9-18dc-5ffb-a494-335386e8da0e",
                "relationship_type": "contained-in"
            }
        ],
        "Attribute": [
            {
                "uuid": "60018778-8234-5728-ab3c-bb7d4facef0c",
                "object_relation": "md5",
                "value": "8764605c6f388c89096b534d33565802",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "3a039c8d-56cb-5ce7-9b07-20db0e806116",
                "object_relation": "sha1",
                "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "eaf4463c-00fa-5d6b-988a-6edd04670e33",
                "object_relation": "sha256",
                "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "a419c3e9-4040-5b47-b8ea-3614315d93b7",
                "object_relation": "filename",
                "value": "oui",
                "type": "filename",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "451ab1b0-5185-5640-9d56-c59eed2fd9ef",
                "object_relation": "file-encoding",
                "value": "UTF-8",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "60b5b0f8-8ae4-5177-92c8-af49a4e7f5f6",
                "object_relation": "size-in-bytes",
                "value": "35",
                "type": "size-in-bytes",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--5e384ae7-672c-4250-9cda-3b4da964451a"
    }
    ```

- identity
  - STIX - Identity
    ```json
    {
        "type": "identity",
        "id": "identity--c2cc2c57-98f5-4804-9e79-8df735f52921",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-01-25T10:18:28.125Z",
        "modified": "2024-01-25T10:18:29.125Z",
        "name": "John Doe",
        "identity_class": "individual"
    }
    ```
  - MISP
    ```json
    {
        "name": "identity",
        "meta-category": "misc",
        "template_uuid": "ae85b960-b507-4de2-a32c-9cfb8f25f990",
        "description": "Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector).  The Identity SDO can capture basic identifying information, contact information, and the sectors that the Identity belongs to. Identity is used in STIX to represent, among other things, targets of attacks, information sources, object creators, and threat actor identities. (ref. STIX 2.1 - 4.5)",
        "template_version": "1",
        "uuid": "c2cc2c57-98f5-4804-9e79-8df735f52921",
        "Attribute": [
            {
                "uuid": "6cf35d44-4f20-5e93-98af-d55674f5694d",
                "object_relation": "name",
                "value": "John Doe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ee29e3cb-f6c0-5901-8bbd-81fab2ee0308",
                "object_relation": "identity_class",
                "value": "individual",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1706177909"
    }
    ```

- network-socket
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:src_ref.value = '1.2.3.4' AND network-traffic:dst_ref.value = '5.6.7.8' AND network-traffic:dst_port = 80 AND network-traffic:src_port = 8080 AND network-traffic:protocols[0] = 'tcp' AND network-traffic:extensions.'socket-ext'.address_family = 'AF_INET' AND network-traffic:extensions.'socket-ext'.socket_type = 'SOCK_RAW' AND network-traffic:extensions.'socket-ext'.is_listening = true]",
        "valid_from": "2020-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "network-socket",
        "meta-category": "network",
        "template_uuid": "48bbfd72-ef8e-4649-b14d-41b4b5a0eba2",
        "description": "Network socket object describes a local or remote network connections based on the socket data structure.",
        "template_version": "4",
        "uuid": "5afb3223-0988-4ef1-a920-02070a00020f",
        "Attribute": [
            {
                "uuid": "69b48f08-e44a-5c8c-b420-e70810c7f9e9",
                "object_relation": "ip-src",
                "value": "1.2.3.4",
                "type": "ip-src",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "2bb3dbe0-2687-524f-9fa8-cf673c3c704e",
                "object_relation": "ip-dst",
                "value": "5.6.7.8",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "06558483-7d3e-59e3-8a75-eb7cc0c6d339",
                "object_relation": "dst-port",
                "value": "80",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "860b4d8f-a159-537d-aa78-fd4ce69c8648",
                "object_relation": "src-port",
                "value": "8080",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "89e671c4-f579-5d2c-a83b-70f9217998a7",
                "object_relation": "protocol",
                "value": "tcp",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "88565fbe-2a16-53fd-b978-40544c12eef1",
                "object_relation": "address-family",
                "value": "AF_INET",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "6b811fbb-929d-5541-a4b3-30e326f80826",
                "object_relation": "socket-type",
                "value": "SOCK_RAW",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "35ae6c2c-fd43-5890-952f-d37ff3644beb",
                "object_relation": "state",
                "value": "listening",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- network-traffic
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--f6a7b8c9-d0e1-4f2a-bb4c-5d6e7f809102",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive network traffic indicator",
        "description": "Network traffic indicator covering src/dst refs, ports, protocols, and byte counts.",
        "pattern": "[network-traffic:src_ref.value = '203.0.113.1' AND network-traffic:dst_ref.value = '198.51.100.34' AND network-traffic:src_port = 2487 AND network-traffic:dst_port = 53 AND network-traffic:protocols[0] = 'ipv4' AND network-traffic:protocols[1] = 'udp' AND network-traffic:protocols[2] = 'dns' AND network-traffic:src_byte_count = 35779 AND network-traffic:dst_byte_count = 935750]",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "network-traffic",
        "meta-category": "network",
        "template_uuid": "16290b18-9af5-4a43-b195-75fe1eef0c35",
        "description": "Generic network traffic that originates from a source and is addressed to a destination.",
        "template_version": "1",
        "uuid": "f6a7b8c9-d0e1-4f2a-bb4c-5d6e7f809102",
        "Attribute": [
            {
                "uuid": "84f5dd45-c1ef-5bb1-bfc3-a26cc1f33096",
                "object_relation": "src_ip",
                "value": "203.0.113.1",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "58862853-e6c6-5200-9809-83b23b64606b",
                "object_relation": "dst_ip",
                "value": "198.51.100.34",
                "type": "ip-dst",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "c91a1ed5-e7ac-5ec2-871f-290504e4d921",
                "object_relation": "src_port",
                "value": "2487",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "1edde4aa-f12e-5725-a16d-ab652e351777",
                "object_relation": "dst_port",
                "value": "53",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "a325a9d9-b485-56db-970e-80bf3a129f1c",
                "object_relation": "protocol",
                "value": "ipv4",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "5766b8be-6ef3-5a74-b5a4-031df19532ed",
                "object_relation": "protocol",
                "value": "udp",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "f3957a5f-4694-5950-aa69-5dcdb0714262",
                "object_relation": "protocol",
                "value": "dns",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "bece9593-04a4-542c-9ec4-822fac94cc5e",
                "object_relation": "src_byte_count",
                "value": "35779",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "a0f99bc0-1ec7-50fd-af9e-c6e2ad0e6cfd",
                "object_relation": "dst_byte_count",
                "value": "935750",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-11-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-11-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "ipv4-addr",
                "value": "198.51.100.2"
            },
            "1": {
                "type": "ipv4-addr",
                "value": "203.0.113.1"
            },
            "2": {
                "type": "ipv4-addr",
                "value": "203.0.113.2"
            },
            "3": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "1",
                "src_port": 2487,
                "dst_port": 1723,
                "protocols": [
                    "ipv4",
                    "pptp"
                ],
                "src_byte_count": 35779,
                "dst_byte_count": 935750,
                "encapsulates_refs": [
                    "4"
                ]
            },
            "4": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "2",
                "src_port": 24678,
                "dst_port": 80,
                "protocols": [
                    "ipv4",
                    "tcp",
                    "http"
                ],
                "src_packets": 14356,
                "dst_packets": 14356,
                "encapsulated_by_ref": "3"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "network-traffic",
        "meta-category": "network",
        "template_uuid": "16290b18-9af5-4a43-b195-75fe1eef0c35",
        "description": "Generic network traffic that originates from a source and is addressed to a destination.",
        "template_version": "1",
        "uuid": "4978b360-df7b-574d-8581-b9118d2cabcd",
        "ObjectReference": [
            {
                "uuid": "619c7ef7-ab56-5ff2-af6f-95ee877d0e01",
                "object_uuid": "4978b360-df7b-574d-8581-b9118d2cabcd",
                "referenced_uuid": "1ae2c084-4e23-52b5-935b-c3404778fa88",
                "relationship_type": "encapsulates"
            }
        ],
        "Attribute": [
            {
                "uuid": "b1b35980-c49a-52df-9cba-6f64fea35a72",
                "object_relation": "src_port",
                "value": "2487",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "1a10c019-191d-585e-b2f3-bfc6f57b3da7",
                "object_relation": "dst_port",
                "value": "1723",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "8e9e0289-3742-52eb-8620-9f9ec4e2528f",
                "object_relation": "src_byte_count",
                "value": "35779",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "7801c3f8-f3cd-5bfc-bca0-560e9a5c2413",
                "object_relation": "dst_byte_count",
                "value": "935750",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "31be520b-1439-50c6-8324-d2510320b2a0",
                "object_relation": "protocol",
                "value": "IPV4",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "7b9ae389-c0ff-5d3d-b57c-66cabf628e04",
                "object_relation": "protocol",
                "value": "PPTP",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "c7ae5a56-ed9c-5a7f-bfa8-5b72f6e3c466",
                "object_relation": "src_ip",
                "value": "198.51.100.2",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "0b14f493-3230-5cd7-866e-c7632f12d440",
                "object_relation": "dst_ip",
                "value": "203.0.113.1",
                "type": "ip-dst",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1606321320",
        "first_seen": "2020-10-25T16:22:00+00:00",
        "last_seen": "2020-11-25T16:22:00+00:00",
        "comment": "Observed Data ID: observed-data--3cd23a7b-a099-49df-b397-189018311d4e"
    }
    ```

- process
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive process indicator",
        "description": "Process indicator covering pid, name, cwd, created, command_line, and binary_ref.",
        "pattern": "[process:pid = 2107 AND process:name = 'Friends_From_H' AND process:cwd = '/home/viktor' AND process:created = '2017-05-01T08:00:00Z' AND process:command_line = 'grep -nrG iglocska ${HOME}/friends.txt']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "process",
        "meta-category": "misc",
        "template_uuid": "02aeef94-ac23-455c-addb-731757ceafb5",
        "description": "Object describing a system process.",
        "template_version": "10",
        "uuid": "a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213",
        "Attribute": [
            {
                "uuid": "d5a8a4e9-0f8e-59e1-9f7a-d34f94f7b8c7",
                "object_relation": "pid",
                "value": "2107",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "1ccb6cc3-b375-570a-ada1-dc61191615c4",
                "object_relation": "name",
                "value": "Friends_From_H",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "c47f519e-404e-5a7c-81d3-d69b5100c364",
                "object_relation": "current-directory",
                "value": "/home/viktor",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "e2272cf2-ec66-54ec-bb35-5322c2e132b5",
                "object_relation": "creation-time",
                "value": "2017-05-01T08:00:00+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "5df63d30-118d-5cab-874f-424c04fae863",
                "object_relation": "command-line",
                "value": "grep -nrG iglocska ${HOME}/friends.txt",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "process",
                "pid": 666,
                "name": "SatanProcess",
                "command_line": "rm -rf *"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "process",
        "meta-category": "misc",
        "template_uuid": "02aeef94-ac23-455c-addb-731757ceafb5",
        "description": "Object describing a system process.",
        "template_version": "10",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "c944d114-650b-5f3b-8ecf-4c7af1332fad",
                "object_relation": "command-line",
                "value": "rm -rf *",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "d5847b7b-c3c6-5a4e-ad5d-dbf3f2f610fd",
                "object_relation": "name",
                "value": "SatanProcess",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b23965e1-8043-565b-af1d-29c500063fce",
                "object_relation": "pid",
                "value": "666",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- registry-key
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[windows-registry-key:key = 'hkey_local_machine\\\\system\\\\foo\\\\fortytwo' AND windows-registry-key:modified_time = '2018-10-25T16:22:00Z' AND windows-registry-key:values[0].name = 'FortyTwoFoo' AND windows-registry-key:values[0].data = '%DATA%\\\\42' AND windows-registry-key:values[0].data_type = 'REG_QWORD']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "registry-key",
        "meta-category": "file",
        "template_uuid": "8b3228ad-6d82-4fe6-b2ae-05426308f1d5",
        "description": "Registry key object describing a Windows registry key with value and last-modified timestamp",
        "template_version": "5",
        "uuid": "28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "Attribute": [
            {
                "uuid": "04a7b009-c2f3-5ffb-b87c-fe5af7b4b0e4",
                "object_relation": "key",
                "value": "hkey_local_machine\\system\\foo\\fortytwo",
                "type": "regkey",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "20a96891-5fbe-5b0d-b7a5-f25d8e7c5edb",
                "object_relation": "last-modified",
                "value": "2018-10-25T16:22:00+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "bb89a36d-dd44-5fa0-94c4-4f2f4ca28558",
                "object_relation": "name",
                "value": "FortyTwoFoo",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "068eb711-5f12-5132-93da-9c6a3d0ab677",
                "object_relation": "data",
                "value": "%DATA%\\42",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": true
            },
            {
                "uuid": "d32b0bc0-ae8f-59f1-a4d2-f791b82a3464",
                "object_relation": "data-type",
                "value": "REG_QWORD",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": true,
                "to_ids": true
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920",
        "first_seen": "2024-10-25T16:22:00+00:00"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "windows-registry-key",
                "key": "hkey_local_machine\\system\\foo\\fortytwo",
                "values": [
                    {
                        "name": "FortyTwoFoo",
                        "data": "%DATA%\\42",
                        "data_type": "REG_QWORD"
                    }
                ],
                "modified": "2020-10-25T16:22:00Z"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "registry-key",
        "meta-category": "file",
        "template_uuid": "8b3228ad-6d82-4fe6-b2ae-05426308f1d5",
        "description": "Registry key object describing a Windows registry key with value and last-modified timestamp",
        "template_version": "5",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "06c5b05e-5cfa-5bd7-8b2b-6e554ca40ff0",
                "object_relation": "key",
                "value": "hkey_local_machine\\system\\foo\\fortytwo",
                "type": "regkey",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "7d0ae455-f759-58ff-8de2-9f6a9b882bfa",
                "object_relation": "last-modified",
                "value": "2020-10-25T16:22:00+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "c424f03a-83c8-5799-bac6-66ae71f6cc51",
                "object_relation": "data",
                "value": "%DATA%\\42",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "c956fe72-f7eb-5835-a58a-3b14accba078",
                "object_relation": "data-type",
                "value": "REG_QWORD",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "6c10b585-3300-5a6d-96eb-68d9b6d92d54",
                "object_relation": "name",
                "value": "FortyTwoFoo",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- software
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--c9d0e1f2-a3b4-4c5d-ae7f-809102132435",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive software indicator",
        "description": "Software indicator covering name, cpe, swid, languages, vendor, and version.",
        "pattern": "[software:name = 'Acrobat X Pro' AND software:cpe = 'cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*' AND software:swid = '<?xml version=\\'1.0\\' encoding=\\'utf-8\\'?><swid:software_identification_tag xsi:schemaLocation=\\'https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd\\'xmlns:swid=\\'https://standards.iso.org/iso/19770/-2/2008/schema.xsd\\' xmlns:xsi=\\'https://www.w3.org/2001/XMLSchema-instance\\'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>' AND software:languages[0] = 'C#' AND software:vendor = 'Adobe Inc.' AND software:version = '10.0']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "software",
        "meta-category": "misc",
        "template_uuid": "b1b5dc0e-73fe-443c-8d9d-0e208de3951e",
        "description": "The Software object represents high-level properties associated with software, including software products. STIX 2.1 - 6.14",
        "template_version": "1",
        "uuid": "c9d0e1f2-a3b4-4c5d-ae7f-809102132435",
        "Attribute": [
            {
                "uuid": "ec5a884a-84a5-573b-b232-1a81fe42e078",
                "object_relation": "name",
                "value": "Acrobat X Pro",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "6080a12f-3ab9-56ad-a0c6-f808a3279a2b",
                "object_relation": "cpe",
                "value": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
                "type": "cpe",
                "disable_correlation": false,
                "to_ids": true,
                "category": "External analysis"
            },
            {
                "uuid": "047c1637-e90d-5278-abb5-23b13f13e496",
                "object_relation": "swid",
                "value": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "14f69580-3d48-5de5-9084-7fdccb6a665c",
                "object_relation": "language",
                "value": "C#",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "fc0fb38d-2751-5f7a-89b1-975b2f2c3e11",
                "object_relation": "vendor",
                "value": "Adobe Inc.",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "83971397-8e8b-584a-bb12-f30523195c97",
                "object_relation": "version",
                "value": "10.0",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "software",
                "name": "Acrobat X Pro",
                "cpe": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
                "languages": [
                    "C#",
                    "Javascript",
                    "Postscript"
                ],
                "vendor": "Adobe Inc.",
                "version": "10.0",
                "swid": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>"
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "software",
        "meta-category": "misc",
        "template_uuid": "b1b5dc0e-73fe-443c-8d9d-0e208de3951e",
        "description": "The Software object represents high-level properties associated with software, including software products. STIX 2.1 - 6.14",
        "template_version": "1",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "f1227ef3-69e9-5528-8c29-fb8f1bb6b98c",
                "object_relation": "cpe",
                "value": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
                "type": "cpe",
                "disable_correlation": false,
                "to_ids": false,
                "category": "External analysis"
            },
            {
                "uuid": "e840214e-b2fa-545a-a477-e6b77663757c",
                "object_relation": "language",
                "value": "C#",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e4d1db9d-76dd-5659-9f8f-602545cee20e",
                "object_relation": "language",
                "value": "Javascript",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "d675d1e5-6fe4-58ac-8614-e359600de96b",
                "object_relation": "language",
                "value": "Postscript",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "48b321bb-013e-5a29-889c-9c078c29966d",
                "object_relation": "name",
                "value": "Acrobat X Pro",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "aa1c917c-c547-5e65-9dd6-13c41ecdff32",
                "object_relation": "swid",
                "value": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ab6bc668-e6e5-5784-9843-a7bf7f5a238f",
                "object_relation": "vendor",
                "value": "Adobe Inc.",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "18436c0b-edf8-5510-8da4-42534019e8e2",
                "object_relation": "version",
                "value": "10.0",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- user-account
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--d0e1f2a3-b4c5-4d6e-bf80-910213243546",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive user account indicator",
        "description": "User account indicator covering user_id, account_login, account_type, display_name, booleans, and timestamps.",
        "pattern": "[user-account:user_id = '1001' AND user-account:account_login = 'jdoe' AND user-account:account_type = 'unix' AND user-account:display_name = 'John Doe' AND user-account:is_service_account = false AND user-account:is_privileged = false AND user-account:can_escalate_privs = true AND user-account:account_created = '2016-01-20T12:31:12Z' AND user-account:credential_last_changed = '2016-01-20T14:27:43Z' AND user-account:account_first_login = '2016-01-20T14:26:07Z' AND user-account:account_last_login = '2016-07-22T16:08:28Z']",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "template_uuid": "49606b06-22f0-4ac8-8eee-2f12ad46f3d3",
        "description": "User-account object, defining aspects of user identification, authentication, privileges and other relevant data points.",
        "template_version": "6",
        "uuid": "d0e1f2a3-b4c5-4d6e-bf80-910213243546",
        "Attribute": [
            {
                "uuid": "def7c5d9-5c68-5a4d-9a4f-a0b45a37785e",
                "object_relation": "user-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "f7058822-7d02-5dde-ad2b-bd66c9c448c5",
                "object_relation": "username",
                "value": "jdoe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "0d54be63-c590-5bf6-bff4-6788f1d4eaf9",
                "object_relation": "account-type",
                "value": "unix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "c7a77322-fcff-5d81-8907-8c5b25a6e14f",
                "object_relation": "display-name",
                "value": "John Doe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "a6ce2cbe-756d-5bbb-9419-bbd7c7fb2ef4",
                "object_relation": "is_service_account",
                "value": "false",
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "a69423b2-aaec-5a97-8b15-b05994b016d7",
                "object_relation": "privileged",
                "value": "false",
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "7b9cb8e3-450b-53c6-b4af-545a755ff723",
                "object_relation": "can_escalate_privs",
                "value": "true",
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "b7c4b3fc-03d6-54e6-8480-5cfc4c639a9b",
                "object_relation": "created",
                "value": "2016-01-20T12:31:12+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "bae20de5-8bd0-5df8-88a1-c760eb8a6c52",
                "object_relation": "password_last_changed",
                "value": "2016-01-20T14:27:43+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "63261757-1933-5d59-bba2-56c5e40bbc99",
                "object_relation": "first_login",
                "value": "2016-01-20T14:26:07+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "8859a971-e9de-5f1e-8b44-4b102e6dbd4d",
                "object_relation": "last_login",
                "value": "2016-07-22T16:08:28+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1001",
                "account_login": "jdoe",
                "account_type": "unix",
                "display_name": "John Doe",
                "is_service_account": false,
                "is_privileged": false,
                "can_escalate_privs": true,
                "extensions": {
                    "unix-account-ext": {
                        "gid": 1001,
                        "groups": [
                            "wheel"
                        ],
                        "home_dir": "/home/jdoe",
                        "shell": "/bin/bash"
                    }
                }
            }
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "template_uuid": "49606b06-22f0-4ac8-8eee-2f12ad46f3d3",
        "description": "User-account object, defining aspects of user identification, authentication, privileges and other relevant data points.",
        "template_version": "6",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "3a76338f-b365-5eac-9992-1f003373c4f1",
                "object_relation": "username",
                "value": "jdoe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b7e55937-e000-5b8a-8964-5b5bb24b96e4",
                "object_relation": "account-type",
                "value": "unix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "c38fd120-58a5-5b71-9828-0d506841a576",
                "object_relation": "can_escalate_privs",
                "value": true,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8bde9f3c-6237-5ab3-ba66-66f5552dcfe8",
                "object_relation": "display-name",
                "value": "John Doe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "bc457973-9d32-5d25-acfb-604e500e7f22",
                "object_relation": "privileged",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "d85b1715-71b6-5f9e-b9ad-187c69ce3c0f",
                "object_relation": "is_service_account",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4f60ba02-9f41-5f35-a41b-43019d810ae6",
                "object_relation": "user-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "6cf3076f-c981-5df9-adcc-58c7b12082d0",
                "object_relation": "group-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9ebb9fdf-c146-5337-bd90-2be77dea36bd",
                "object_relation": "group",
                "value": "wheel",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "10a199c5-74fc-5219-8f2e-ef045debe1e6",
                "object_relation": "home_dir",
                "value": "/home/jdoe",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "5130cfec-ff6d-50b8-9deb-dbe7d05f7248",
                "object_relation": "shell",
                "value": "/bin/bash",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```

- x509
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "id": "indicator--e1f2a3b4-c5d6-4e7f-8091-021324354657",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive X.509 certificate indicator",
        "description": "X.509 certificate indicator covering is_self_signed, hashes, version, serial_number, signature_algorithm, issuer, validity, subject, and public key fields.",
        "pattern": "[x509-certificate:is_self_signed = false AND x509-certificate:hashes.MD5 = '219794f8f6128c731f476d11e7fa5d4f' AND x509-certificate:hashes.'SHA-1' = 'd02be9aa68a05fdf7e99899a9719f275db5e6b2f' AND x509-certificate:hashes.'SHA-256' = '0adb35fcd170c6da0e45a00c9b36533b21dc2bcf793e6facf0eb30829cbcc5fb' AND x509-certificate:version = '3' AND x509-certificate:serial_number = '00:bc:b4:e7:32:76:0e:ca:64:31:8e:17:6c:fd:4a:ef:30' AND x509-certificate:signature_algorithm = 'sha256WithRSAEncryption' AND x509-certificate:issuer = '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Code Signing CA' AND x509-certificate:validity_not_before = '2015-12-08T00:00:00Z' AND x509-certificate:validity_not_after = '2016-12-07T23:59:59Z' AND x509-certificate:subject = '/C=GB/postalCode=RG12 2LS/ST=Berkshire/L=Bracknell/street=15  Shepherds Hill/postOfficeBox=RG12 2LS/O=Network Software Ltd/CN=Network Software Ltd' AND x509-certificate:subject_public_key_algorithm = 'sha256WithRSAEncryption' AND x509-certificate:subject_public_key_modulus = '00:ae:29:f8:d7:56:2f:fd:61:40:89:6f:cc:a3:1c:e0:49:0c:21:9f:5e:60:0c:a9:dc:cf:5f:79:83:fd:12:8f:f3:fc:c1:49:a3:e2:9c:a8:e9:d2:88:44:16:bd:39:2e:23:5b:84:e9:54:70:4b:ce:e3:c2:19:fd:a4:8b:45:ca:ad:aa:08:ae:cc:ab:8f:eb:60:74:fa:e0:2b:e5:d1:7b:5d:87:43:26:71:96:d1:ec:5f:23:15:40:37:0e:cc:b1:e1:5a:57:f1:24:58:2c:d6:04:f3:8e:34:9a:ea:bb:88:d5:9b:c3:38:8d:e4:90:7b:e7:ef:89:ea:31:92:97:46:80:f9:f8:b2:78:53:19:b8:66:15:37:af:32:08:58:3f:42:1a:67:f5:9a:40:b7:25:75:dc:3c:5f:b1:7c:12:63:f8:2b:60:93:b5:04:c4:10:9c:2d:1f:aa:9f:af:b1:e9:ee:70:21:fb:7e:aa:b3:1a:8e:e4:4c:18:6e:6a:5d:c4:61:e3:bd:83:d2:af:c6:ce:bc:f8:b8:0f:db:e0:9e:ec:f4:e2:61:99:ee:81:63:d1:71:e4:a7:2b:de:5c:0a:6d:2e:33:94:50:1f:33:e9:bb:1c:eb:e6:d2:18:3d:4f:02:02:dc:30:2e:52:19:4f:9c:0d:15:9d:56:f1:cb:30:59:57' AND x509-certificate:subject_public_key_exponent = 65537]",
        "valid_from": "2024-10-25T16:22:00Z",
        "labels": [
            "malicious-activity"
        ]
    }
    ```
  - MISP
    ```json
    {
        "name": "x509",
        "meta-category": "network",
        "template_uuid": "d1ab756a-26b5-4349-9f43-765630f0911c",
        "description": "x509 object describing a X.509 certificate",
        "template_version": "14",
        "uuid": "e1f2a3b4-c5d6-4e7f-8091-021324354657",
        "Attribute": [
            {
                "uuid": "fcaaa31c-f344-5c32-90b3-758a92f3d13a",
                "object_relation": "self_signed",
                "value": "false",
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "3f0bd61e-1d19-50da-9f26-3c31412db4f7",
                "object_relation": "x509-fingerprint-md5",
                "value": "219794f8f6128c731f476d11e7fa5d4f",
                "type": "x509-fingerprint-md5",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "e7e75d50-bcd4-5272-b35a-5bf955e5315a",
                "object_relation": "x509-fingerprint-sha1",
                "value": "d02be9aa68a05fdf7e99899a9719f275db5e6b2f",
                "type": "x509-fingerprint-sha1",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "f8fbd361-0c45-5ea2-8c32-930cd2b9e038",
                "object_relation": "x509-fingerprint-sha256",
                "value": "0adb35fcd170c6da0e45a00c9b36533b21dc2bcf793e6facf0eb30829cbcc5fb",
                "type": "x509-fingerprint-sha256",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Network activity"
            },
            {
                "uuid": "9c32d2f4-bb8a-55e5-b818-df39542dd359",
                "object_relation": "version",
                "value": "3",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "ec5cc4f9-a50d-5308-a0c5-310f9dedf3fd",
                "object_relation": "serial-number",
                "value": "00:bc:b4:e7:32:76:0e:ca:64:31:8e:17:6c:fd:4a:ef:30",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "c32c9d95-d54d-5f94-ab3f-f09f9257e166",
                "object_relation": "signature_algorithm",
                "value": "sha256WithRSAEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "5325b180-9bcd-5a76-be4d-18c0368b2e35",
                "object_relation": "issuer",
                "value": "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Code Signing CA",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "ff1fd92b-fcbb-5f2b-a332-ca77dd73574c",
                "object_relation": "validity-not-before",
                "value": "2015-12-08T00:00:00+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "cdb11267-69b2-53bd-b4bc-f888ddc37ce7",
                "object_relation": "validity-not-after",
                "value": "2016-12-07T23:59:59+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "153fbe0e-5cac-5658-a7bf-5496db52361b",
                "object_relation": "subject",
                "value": "/C=GB/postalCode=RG12 2LS/ST=Berkshire/L=Bracknell/street=15  Shepherds Hill/postOfficeBox=RG12 2LS/O=Network Software Ltd/CN=Network Software Ltd",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "669a8f79-9a4c-5df7-b364-3bf551975463",
                "object_relation": "pubkey-info-algorithm",
                "value": "sha256WithRSAEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "a9277d40-7204-5340-bb0d-e960938b3d51",
                "object_relation": "pubkey-info-modulus",
                "value": "00:ae:29:f8:d7:56:2f:fd:61:40:89:6f:cc:a3:1c:e0:49:0c:21:9f:5e:60:0c:a9:dc:cf:5f:79:83:fd:12:8f:f3:fc:c1:49:a3:e2:9c:a8:e9:d2:88:44:16:bd:39:2e:23:5b:84:e9:54:70:4b:ce:e3:c2:19:fd:a4:8b:45:ca:ad:aa:08:ae:cc:ab:8f:eb:60:74:fa:e0:2b:e5:d1:7b:5d:87:43:26:71:96:d1:ec:5f:23:15:40:37:0e:cc:b1:e1:5a:57:f1:24:58:2c:d6:04:f3:8e:34:9a:ea:bb:88:d5:9b:c3:38:8d:e4:90:7b:e7:ef:89:ea:31:92:97:46:80:f9:f8:b2:78:53:19:b8:66:15:37:af:32:08:58:3f:42:1a:67:f5:9a:40:b7:25:75:dc:3c:5f:b1:7c:12:63:f8:2b:60:93:b5:04:c4:10:9c:2d:1f:aa:9f:af:b1:e9:ee:70:21:fb:7e:aa:b3:1a:8e:e4:4c:18:6e:6a:5d:c4:61:e3:bd:83:d2:af:c6:ce:bc:f8:b8:0f:db:e0:9e:ec:f4:e2:61:99:ee:81:63:d1:71:e4:a7:2b:de:5c:0a:6d:2e:33:94:50:1f:33:e9:bb:1c:eb:e6:d2:18:3d:4f:02:02:dc:30:2e:52:19:4f:9c:0d:15:9d:56:f1:cb:30:59:57",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            },
            {
                "uuid": "c2653d55-6121-5056-a6a1-3996d84c9018",
                "object_relation": "pubkey-info-exponent",
                "value": "65537",
                "type": "text",
                "disable_correlation": false,
                "to_ids": true,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1729873320"
    }
    ```
  - STIX - Observed Data
    ```json
    {
        "type": "observed-data",
        "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa952",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "x509-certificate",
                "is_self_signed": false,
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
        }
    }
    ```
  - MISP
    ```json
    {
        "name": "x509",
        "meta-category": "network",
        "template_uuid": "d1ab756a-26b5-4349-9f43-765630f0911c",
        "description": "x509 object describing a X.509 certificate",
        "template_version": "14",
        "uuid": "3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
        "Attribute": [
            {
                "uuid": "50abfecf-2114-5934-ade9-e2b6f6aafa41",
                "object_relation": "x509-fingerprint-md5",
                "value": "09716af84e900e403494c28ad8c5869c",
                "type": "x509-fingerprint-md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "e0e7d2dc-9736-5d9e-b9ce-b234011a12cb",
                "object_relation": "x509-fingerprint-sha1",
                "value": "1456d8a00d8be963e2224d845b12e5084ea0b707",
                "type": "x509-fingerprint-sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "3c98eff2-0f03-5032-b069-79e6e3d4f705",
                "object_relation": "x509-fingerprint-sha256",
                "value": "2d23636c25eb5c1b473e0ae66fdb076687b40bd080f161c79663572f171d5598",
                "type": "x509-fingerprint-sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "9faea658-5e20-5ccb-b462-a4b5b0bb92e1",
                "object_relation": "self_signed",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4483f0c1-2d60-51cd-b9e1-98c88845df4a",
                "object_relation": "issuer",
                "value": "C=US, O=thawte, Inc., CN=thawte SHA256 Code Signing CA",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9f603c79-b538-5cdb-824d-4af959a3d016",
                "object_relation": "serial-number",
                "value": "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "3ab6eb00-7978-5709-bedc-54dffe3a8304",
                "object_relation": "signature_algorithm",
                "value": "sha256WithRSAEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "50af2b28-bdf8-5b54-bd1f-e5c8d023db00",
                "object_relation": "subject",
                "value": "C=GB, ST=London, L=London, O=Ziber Ltd, CN=Ziber Ltd",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "f95584f7-9433-5529-900d-6576fea80d00",
                "object_relation": "pubkey-info-algorithm",
                "value": "rsaEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "dc0856b2-b188-577b-ac7e-41eeb5fc0b92",
                "object_relation": "pubkey-info-exponent",
                "value": "65537",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "feb62035-48e5-578b-987a-0a0451f49215",
                "object_relation": "pubkey-info-modulus",
                "value": "00:e2:12:e4:5c:44:90:fa:0f:75:77:c8:88:51:21:1d:ce:b8:0e:f2:73:d5:68:79:02:50:51:5f:2c:a3:82:d1:48:60:f8:fa:c7:75:72:12:bc:b9:7c:d9:12:a8:1a:18:3a:f9:1d:a9:18:04:59:cd:8a:81:03:f7:0a:3d:22:6e:7d:63:65:d7:4d:c5:65:0e:fc:4f:97:9c:e0:3d:52:a4:d9:0b:d9:04:c3:f3:52:2a:a3:cc:e2:82:2c:2b:b8:54:1b:cc:41:2b:1b:76:d0:2a:fd:65:c4:3f:a2:4b:36:5f:5a:79:28:4b:98:1e:38:6c:b6:33:d2:3d:db:53:9c:0b:3f:2b:ab:87:2e:94:47:72:4f:27:58:8d:b0:b2:38:5f:1d:e0:67:53:6e:38:c7:ac:24:49:c9:b6:81:42:e0:06:95:26:c0:c9:bf:5e:7f:1b:92:f5:58:8e:8a:70:88:a9:e5:82:5c:5c:71:54:e0:74:1b:a9:33:1a:f2:3d:bf:9d:1b:45:1a:0e:02:d8:a3:d8:db:64:a9:f8:28:16:7f:4e:c3:ee:33:a1:be:18:72:e3:bd:79:12:54:ea:b9:77:9b:d0:d0:b0:2d:75:af:4d:47:4e:c1:16:84:a2:88:65:ef:18:ff:33:2a:ab:83:7c:43:14:ad:b8:cd:f0:b9:7c:c1:23",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8a6f864d-0129-5cb7-84a8-812a9510475b",
                "object_relation": "validity-not-after",
                "value": "2018-07-09T23:59:59+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "99d8c362-80bf-5e21-a79d-6606a6b7e122",
                "object_relation": "validity-not-before",
                "value": "2017-07-09T00:00:00+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "78e45f9f-8cf6-5ff4-bd53-0362478599ec",
                "object_relation": "version",
                "value": "3",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920"
    }
    ```


## The other detailed mappings

- [External Attributes mapping](external_stix20_to_misp_attributes.md)
