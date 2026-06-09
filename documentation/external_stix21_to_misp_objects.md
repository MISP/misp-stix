# External STIX 2.1 to MISP Objects mapping

MISP Objects are containers grouping related MISP attributes. When importing external STIX 2.1 content (bundles not produced by MISP), composite STIX structures (an `Indicator` with a multi-field pattern, or an `Observed Data` with referenced SCOs, or standalone SCOs) are mapped to the corresponding MISP object template. In addition, some standalone SDOs are mapped directly to a MISP object: an `Identity` becomes an `identity` (or `organization`) object, a `Malware Analysis` becomes a `malware-analysis` object, and a `Location` carrying geolocation fields becomes a `geolocation` object.

The list of currently supported MISP object templates is available [here](https://github.com/MISP/misp-objects).

### Current mapping

- artifact
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive malicious artifact indicator",
        "description": "Artifact indicator covering mime_type, payload_bin, hashes, and decryption_key.",
        "pattern": "[artifact:mime_type = 'application/zip' AND artifact:payload_bin = 'UEsDBAoACQAAAKBINlgCq9F[...]AAAAQABAEkAAABdAAAAAAA=' AND artifact:hashes.'MD5' = 'bc590af5f7b16b890860248dc0d4c68f' AND artifact:hashes.'SHA-1' = '003d59659a3e28781aaf03da1ac1cb0e326ed65e' AND artifact:hashes.'SHA-256' = '2dd39c08867f34010fd9ea1833aa549a02da16950dda4a8ef922113a9eccd963' AND artifact:decryption_key = 'infected']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
            },
            {
                "uuid": "5b1a53ea-e72a-517b-9d09-fdd81a2b43b6",
                "object_relation": "decryption_key",
                "value": "infected",
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "artifact--8f49b9de-b47d-43fd-b3f8-4976f0d42feb"
            ]
        },
        {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
            "mime_type": "application/zip",
            "payload_bin": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
            "hashes": {
                "MD5": "5bfd0814254d0ff993a83560cb740042",
                "SHA-1": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                "SHA-256": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa"
            },
            "decryption_key": "clear"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "artifact",
        "meta-category": "file",
        "template_uuid": "0a46df3a-bd9b-472c-a1e7-6aede7094483",
        "description": "The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload. From STIX 2.1 (6.1)",
        "template_version": "3",
        "uuid": "8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
        "Attribute": [
            {
                "data": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
                "uuid": "aa1a5b60-8534-5f7e-91dc-5e48dca63885",
                "object_relation": "payload_bin",
                "value": "8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
                "type": "attachment",
                "disable_correlation": false,
                "to_ids": false,
                "category": "External analysis"
            },
            {
                "uuid": "9e939908-da18-5cbe-baaf-ba2bfcbf7b59",
                "object_relation": "md5",
                "value": "5bfd0814254d0ff993a83560cb740042",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "0b575e7f-6759-5b99-a80d-c56bfb5d429e",
                "object_relation": "sha1",
                "value": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "b38dbbe7-e65d-5367-a654-cff1564199e0",
                "object_relation": "sha256",
                "value": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "d0b29f67-8c09-5eee-acf8-7c87f7368dc0",
                "object_relation": "decryption_key",
                "value": "clear",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9fa7eeb9-d1e6-56a1-8d5e-e3aec802e018",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
        "mime_type": "application/zip",
        "payload_bin": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
        "hashes": {
            "MD5": "5bfd0814254d0ff993a83560cb740042",
            "SHA-1": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
            "SHA-256": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa"
        },
        "decryption_key": "clear"
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
        "uuid": "8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
        "Attribute": [
            {
                "data": "UEsDBAoACQAAANVUNlgGfJ2[...]AAAAQABAEkAAABdAAAAAAA=",
                "uuid": "aa1a5b60-8534-5f7e-91dc-5e48dca63885",
                "object_relation": "payload_bin",
                "value": "8f49b9de-b47d-43fd-b3f8-4976f0d42feb",
                "type": "attachment",
                "disable_correlation": false,
                "to_ids": false,
                "category": "External analysis"
            },
            {
                "uuid": "9e939908-da18-5cbe-baaf-ba2bfcbf7b59",
                "object_relation": "md5",
                "value": "5bfd0814254d0ff993a83560cb740042",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "0b575e7f-6759-5b99-a80d-c56bfb5d429e",
                "object_relation": "sha1",
                "value": "5ec1405887e5a74bf2cb97a8d64481194dc13fdc",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "b38dbbe7-e65d-5367-a654-cff1564199e0",
                "object_relation": "sha256",
                "value": "367e474683cb1f61aae1f963aa9a17446afb5f71a8a03dae7203ac84765a5efa",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "d0b29f67-8c09-5eee-acf8-7c87f7368dc0",
                "object_relation": "decryption_key",
                "value": "clear",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9fa7eeb9-d1e6-56a1-8d5e-e3aec802e018",
                "object_relation": "mime_type",
                "value": "application/zip",
                "type": "mime-type",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Artifacts dropped"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- asn
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive autonomous system indicator",
        "description": "Autonomous system indicator covering number and name fields.",
        "pattern": "[autonomous-system:number = 197869 AND autonomous-system:name = 'CIRCL']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
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
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--81294150-8f7a-453d-a1d8-96c2cfe04efa",
            "number": 666,
            "name": "Satan autonomous system"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "asn",
        "meta-category": "network",
        "template_uuid": "4ec55cc6-9e49-4c64-b794-03c25c1a6587",
        "description": "Autonomous system object describing an autonomous system which can include one or more network operators managing an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.",
        "template_version": "6",
        "uuid": "81294150-8f7a-453d-a1d8-96c2cfe04efa",
        "Attribute": [
            {
                "uuid": "61679e52-b420-5f20-a78b-22bffaeddc02",
                "object_relation": "asn",
                "value": "AS666",
                "type": "AS",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "0264dae6-129b-544c-ba3a-bb5399694b23",
                "object_relation": "description",
                "value": "Satan autonomous system",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--81294150-8f7a-453d-a1d8-96c2cfe04efa",
        "number": 666,
        "name": "Satan autonomous system"
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
        "uuid": "81294150-8f7a-453d-a1d8-96c2cfe04efa",
        "Attribute": [
            {
                "uuid": "61679e52-b420-5f20-a78b-22bffaeddc02",
                "object_relation": "asn",
                "value": "AS666",
                "type": "AS",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "0264dae6-129b-544c-ba3a-bb5399694b23",
                "object_relation": "description",
                "value": "Satan autonomous system",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- directory
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive directory indicator",
        "description": "Directory indicator covering path, path_enc, ctime, mtime, and atime.",
        "pattern": "[directory:path = '/var/www/MISP' AND directory:path_enc = 'UTF-8' AND directory:ctime = '2011-11-26T10:45:31Z' AND directory:mtime = '2023-12-12T11:34:05Z' AND directory:atime = '2023-12-12T11:34:05Z']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
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
            "id": "directory--f93cb275-0366-4ecc-abf0-a17928d1e177",
            "path": "/var/www/MISP/app/files/scripts/misp-stix",
            "path_enc": "ISO-8859-1",
            "ctime": "2021-07-21T11:44:56Z",
            "mtime": "2023-12-12T11:24:30Z",
            "atime": "2023-12-12T11:24:30Z"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "directory",
        "meta-category": "file",
        "template_uuid": "23ac6a02-1017-4ea6-a4df-148ed563988d",
        "description": "Directory object describing a directory with meta-information",
        "template_version": "1",
        "uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
        "Attribute": [
            {
                "uuid": "0bc73c79-a7aa-5651-8e4f-459959cafaf8",
                "object_relation": "access-time",
                "value": "2023-12-12T11:24:30+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "14146652-736e-51ba-b087-0526643eeb43",
                "object_relation": "creation-time",
                "value": "2021-07-21T11:44:56+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "cdcff6d7-f3e1-553a-a400-4501dcd8642b",
                "object_relation": "modification-time",
                "value": "2023-12-12T11:24:30+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "1b13ad05-c3bd-5136-a368-88759eabcc88",
                "object_relation": "path",
                "value": "/var/www/MISP/app/files/scripts/misp-stix",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "60138d6e-47eb-503d-80bf-499e8b5b07fb",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--e812789e-e49d-47e2-b334-8ee0e8a766ce"
    }
    ```
  - STIX - Observable
    ```json
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
        "ObjectReference": [
            {
                "uuid": "62fdb4db-20dd-5fa1-b54c-8a35b28938ae",
                "object_uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "referenced_uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
                "relationship_type": "contains"
            }
        ],
        "Attribute": [
            {
                "uuid": "e609e2e7-b3ce-59bb-9624-ef28eb3fc29e",
                "object_relation": "access-time",
                "value": "2023-12-12T11:34:05+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "2fead137-f19d-57de-a3f2-2c092894c04c",
                "object_relation": "creation-time",
                "value": "2014-07-25T10:47:08+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9af339c4-a8ee-5fab-9f21-f6591f0b83bd",
                "object_relation": "modification-time",
                "value": "2023-12-12T11:34:05+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "48e7ee43-3c27-56c1-83e1-669240e1bdb7",
                "object_relation": "path",
                "value": "/var/www/MISP/app/files/scripts",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8383d817-bba9-5eea-b705-4289d777e7f4",
                "object_relation": "path-encoding",
                "value": "ISO-8859-6-I",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- domain-ip
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--d4e1caeb-f5d3-47a7-ac54-5320d2bd706e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Domain with suspicious IP resolution",
        "description": "Domain resolving to a suspicious IP address.",
        "pattern": "[domain-name:value = 'example.com' AND domain-name:resolves_to_refs[*].value = '198.51.100.3']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-11-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-11-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
                "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
                "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1"
            ]
        },
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
            "value": "example.com",
            "resolves_to_refs": [
                "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
                "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1"
            ]
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
            "value": "198.51.100.3"
        },
        {
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "domain-ip",
        "meta-category": "network",
        "template_uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734",
        "description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
        "template_version": "11",
        "uuid": "3c10e93f-798e-5a26-a0c1-08156efab7f5",
        "Attribute": [
            {
                "uuid": "b7b09319-91b3-52f6-b028-750d2a46ec7c",
                "object_relation": "domain",
                "value": "example.com",
                "type": "domain",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "2cd58756-4ce7-5130-ae4d-e105710c0297",
                "object_relation": "ip",
                "value": "198.51.100.3",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "e4219530-082e-5279-ac7d-2aad3b1827a4",
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
  - STIX - Observable
    ```json
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
        "value": "example.com",
        "resolves_to_refs": [
            "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
            "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1"
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
        "uuid": "3c10e93f-798e-5a26-a0c1-08156efab7f5",
        "Attribute": [
            {
                "uuid": "b7b09319-91b3-52f6-b028-750d2a46ec7c",
                "object_relation": "domain",
                "value": "example.com",
                "type": "domain",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "2cd58756-4ce7-5130-ae4d-e105710c0297",
                "object_relation": "ip",
                "value": "198.51.100.3",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "e4219530-082e-5279-ac7d-2aad3b1827a4",
                "object_relation": "ip",
                "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "type": "ip-dst",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- email
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive email message indicator",
        "description": "Email message indicator covering multipart, content_type, date, subject, from/to/cc refs, headers, and body.",
        "pattern": "[email-message:date = '2016-06-19T14:20:40.000Z' AND email-message:subject = 'Check out this picture of a cat!' AND email-message:from_ref.value = 'jdoe@example.com' AND email-message:to_refs[*].value = 'bob@example.com' AND email-message:cc_refs[*].value = 'mary@example.com' AND email-message:additional_header_fields.'X-Mailer' = 'Mutt/1.5.23' AND email-message:body_multipart[0].content_type = 'text/plain; charset=utf-8' AND email-message:body_multipart[0].body = 'Cats are funny!']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-11-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-11-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "email-message--cf9b4b7f-14c8-5955-8065-020e0316b559",
                "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
                "email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868",
                "email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194",
                "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
                "file--6ce09d9c-0ad3-5ebf-900c-e3cb288955b5"
            ]
        },
        {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--cf9b4b7f-14c8-5955-8065-020e0316b559",
            "is_multipart": true,
            "date": "2016-06-19T14:20:40Z",
            "content_type": "multipart/mixed",
            "from_ref": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
            "to_refs": [
                "email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868"
            ],
            "cc_refs": [
                "email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194"
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
                    "body_raw_ref": "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
                    "content_type": "image/png",
                    "content_disposition": "attachment; filename=\"tabby.png\""
                },
                {
                    "body_raw_ref": "file--6ce09d9c-0ad3-5ebf-900c-e3cb288955b5",
                    "content_type": "application/zip",
                    "content_disposition": "attachment; filename=\"tabby_pics.zip\""
                }
            ]
        },
        {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
            "value": "jdoe@example.com",
            "display_name": "John Doe"
        },
        {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868",
            "value": "bob@example.com",
            "display_name": "Bob Smith"
        },
        {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194",
            "value": "mary@example.com",
            "display_name": "Mary Smith"
        },
        {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
            "mime_type": "image/jpeg",
            "payload_bin": "iVBORw0KGgoAAAANSUhEUgAAADQAAAAkCAYAAADGrhlwAAAMP2lDQ1BJQ0MgUHJvZmlsZQAASImVVwdYU8kWnltSIQQIICAl9CaISAkgJYQWQHoRbIQkQCgxBoKKHV1UcO0iAjZ0VUSxA2JH7CyKvS8WFJR1sWBX3qSArvvK9+b75s5//znznzPnztx7BwD6CZ5EkoNqApArzpfGhgQwxySnMEldgADogAyGAhseP0/Cjo6OALAMtH8v724ARN5edZRr/bP/vxYtgTCPDwASDXGaII+fC/EBAPAqvkSaDwBRzltMyZfIMaxARwoDhHihHGcocZUcpynxHoVNfCwH4hYAyOo8njQDAI3LkGcW8DOghkYvxM5igUgMAJ0JsW9u7iQBxKkQ20IbCcRyfVbaDzoZf9NMG9Tk8TIGsXIuikIOFOVJcnjT/s90/O+SmyMb8GENq3qmNDRWPmeYt1vZk8LlWB3iHnFaZBTE2hB/EAkU9hCj1ExZaILSHjXi53FgzoAexM4CXmA4xEYQB4tzIiNUfFq6KJgLMVwh6FRRPjceYn2IFwrzguJUNhulk2JVvtD6dCmHreLP8aQKv3JfD2TZCWyV/utMIVelj2kUZsYnQUyF2LJAlBgJsQbETnnZceEqm1GFmZzIARupLFYevyXEsUJxSIBSHytIlwbHquxLcvMG5ottzBRxI1V4X35mfKgyP1gLn6eIH84FuywUsxMGdIR5YyIG5iIQBgYp5451CcUJcSqdD5L8gFjlWJwqyYlW2ePmwpwQOW8OsWteQZxqLJ6YDxekUh9Pl+RHxyvjxAuzeGHRynjwZSACcEAgYAIZrGlgEsgCoraehh54p+wJBjwgBRlACBxVzMCIJEWPGF7jQCH4EyIhyBscF6DoFYICyH8dZJVXR5Cu6C1QjMgGTyHOBeEgB97LFKPEg94SwRPIiP7hnQcrH8abA6u8/9/zA+x3hg2ZCBUjG/DIpA9YEoOIgcRQYjDRDjfEfXFvPAJe/WF1wVm458A8vtsTnhLaCY8I1wkdhNsTRUXSn6IcDTqgfrAqF2k/5gK3hppueADuA9WhMq6HGwJH3BX6YeN+0LMbZDmquOVZYf6k/bcZ/PA0VHYUZwpKGULxp9j+PFLDXsNtUEWe6x/zo4w1bTDfnMGen/1zfsi+ALbhP1tiC7H92FnsJHYeO4I1ACZ2HGvEWrGjcjy4up4oVteAt1hFPNlQR/QPfwNPVp7JPOda527nL8q+fOFU+TsacCZJpklFGZn5TDb8IgiZXDHfaRjTxdnFFQD590X5+noTo/huIHqt37l5fwDgc7y/v//wdy7sOAB7PeD2P/Sds2XBT4caAOcO8WXSAiWHyy8E+Jagw51mAEyABbCF83EB7sAb+IMgEAaiQDxIBhNg9JlwnUvBFDADzAXFoBQsA6tBBdgANoPtYBfYBxrAEXASnAEXwWVwHdyFq6cTvAC94B34jCAICaEhDMQAMUWsEAfEBWEhvkgQEoHEIslIKpKBiBEZMgOZh5QiK5AKZBNSg+xFDiEnkfNIO3IbeYh0I6+RTyiGqqM6qDFqjQ5HWSgbDUfj0fFoBjoZLUTno0vQcrQa3YnWoyfRi+h1tAN9gfZhAFPD9DAzzBFjYRwsCkvB0jEpNgsrwcqwaqwOa4LP+SrWgfVgH3EizsCZuCNcwaF4As7HJ+Oz8MV4Bb4dr8db8Kv4Q7wX/0agEYwIDgQvApcwhpBBmEIoJpQRthIOEk7DvdRJeEckEvWINkQPuBeTiVnE6cTFxHXE3cQTxHbiY2IfiUQyIDmQfEhRJB4pn1RMWkvaSTpOukLqJH0gq5FNyS7kYHIKWUwuIpeRd5CPka+Qn5E/UzQpVhQvShRFQJlGWUrZQmmiXKJ0Uj5Ttag2VB9qPDWLOpdaTq2jnqbeo75RU1MzV/NUi1ETqc1RK1fbo3ZO7aHaR3VtdXt1jvo4dZn6EvVt6ifUb6u/odFo1jR/Wgotn7aEVkM7RXtA+6DB0HDS4GoINGZrVGrUa1zReEmn0K3obPoEeiG9jL6ffoneo0nRtNbkaPI0Z2lWah7SvKnZp8XQGqEVpZWrtVhrh9Z5rS5tkra1dpC2QHu+9mbtU9qPGRjDgsFh8BnzGFsYpxmdOkQdGx2uTpZOqc4unTadXl1tXVfdRN2pupW6R3U79DA9az2uXo7eUr19ejf0Pg0xHsIeIhyyaEjdkCtD3usP1ffXF+qX6O/Wv67/yYBpEGSQbbDcoMHgviFuaG8YYzjFcL3hacOeoTpDvYfyh5YM3Tf0jhFqZG8UazTdaLNRq1GfsYlxiLHEeK3xKeMeEz0Tf5Msk1Umx0y6TRmmvqYi01Wmx02fM3WZbGYOs5zZwuw1MzILNZOZbTJrM/tsbmOeYF5kvtv8vgXVgmWRbrHKotmi19LUcrTlDMtayztWFCuWVabVGquzVu+tbayTrBdYN1h32ejbcG0KbWpt7tnSbP1sJ9tW216zI9qx7LLt1tldtkft3ewz7SvtLzmgDu4OIod1Du3DCMM8h4mHVQ+76ajuyHYscKx1fOik5xThVOTU4PRyuOXwlOHLh58d/s3ZzTnHeYvz3RHaI8JGFI1oGvHaxd6F71Lpcm0kbWTwyNkjG0e+cnVwFbqud73lxnAb7bbArdntq7uHu9S9zr3bw9Ij1aPK4yZLhxXNWsw650nwDPCc7XnE86OXu1e+1z6vv7wdvbO9d3h3jbIZJRy1ZdRjH3Mfns8mnw5fpm+q70bfDj8zP55ftd8jfwt/gf9W/2dsO3YWeyf7ZYBzgDTgYMB7jhdnJudEIBYYElgS2BakHZQQVBH0INg8OCO4Nrg3xC1kesiJUEJoeOjy0JtcYy6fW8PtDfMImxnWEq4eHhdeEf4owj5CGtE0Gh0dNnrl6HuRVpHiyIYoEMWNWhl1P9omenL04RhiTHRMZczT2BGxM2LPxjHiJsbtiHsXHxC/NP5ugm2CLKE5kZ44LrEm8X1SYNKKpI4xw8fMHHMx2TBZlNyYQkpJTNma0jc2aOzqsZ3j3MYVj7sx3mb81PHnJxhOyJlwdCJ9Im/i/lRCalLqjtQvvCheNa8vjZtWldbL5/DX8F8I/AWrBN1CH+EK4bN0n/QV6V0ZPhkrM7oz/TLLMntEHFGF6FVWaNaGrPfZUdnbsvtzknJ255JzU3MPibXF2eKWSSaTpk5qlzhIiiUdk70mr57cKw2Xbs1D8sbnNebrwB/5Vpmt7BfZwwLfgsqCD1MSp+yfqjVVPLV1mv20RdOeFQYX/jYdn86f3jzDbMbcGQ9nsmdumoXMSpvVPNti9vzZnXNC5myfS52bPff3IueiFUVv5yXNa5pvPH/O/Me/hPxSW6xRLC2+ucB7wYaF+ELRwrZFIxetXfStRFByodS5tKz0y2L+4gu/jvi1/Nf+JelL2pa6L12/jLhMvOzGcr/l21dorShc8Xjl6JX1q5irSla9XT1x9fky17INa6hrZGs6yiPKG9darl229ktFZsX1yoDK3VVGVYuq3q8TrLuy3n993QbjDaUbPm0Ubby1KWRTfbV1ddlm4uaCzU+3JG45+xvrt5qthltLt37dJt7WsT12e0uNR03NDqMdS2vRWllt985xOy/vCtzVWOdYt2m33u7SPWCPbM/zval7b+wL39e8n7W/7oDVgaqDjIMl9Uj9tPrehsyGjsbkxvZDYYeam7ybDh52OrztiNmRyqO6R5ceox6bf6z/eOHxvhOSEz0nM04+bp7YfPfUmFPXWmJa2k6Hnz53JvjMqbPss8fP+Zw7ct7r/KELrAsNF90v1re6tR783e33g23ubfWXPC41Xva83NQ+qv3YFb8rJ68GXj1zjXvt4vXI6+03Em7cujnuZsctwa2u2zm3X90puPP57px7hHsl9zXvlz0welD9h90fuzvcO44+DHzY+iju0d3H/McvnuQ9+dI5/yntadkz02c1XS5dR7qDuy8/H/u884Xkxeee4j+1/qx6afvywF/+f7X2juntfCV91f968RuDN9veur5t7ovue/Au993n9yUfDD5s/8j6ePZT0qdnn6d8IX0p/2r3telb+Ld7/bn9/RKelKf4FcBgRdPTAXi9DQBaMgAMeD6jjlWe/xQFUZ5ZFQj8J6w8IyqKOwB18P89pgf+3dwEYM8WePyC+vRxAETTAIj3BOjIkYN14KymOFfKCxGeAzZGfU3LTQP/pijPnD/E/XML5Kqu4Of2X0krfGlwjnGBAAAAimVYSWZNTQAqAAAACAAEARoABQAAAAEAAAA+ARsABQAAAAEAAABGASgAAwAAAAEAAgAAh2kABAAAAAEAAABOAAAAAAAAAJAAAAABAAAAkAAAAAEAA5KGAAcAAAASAAAAeKACAAQAAAABAAAANKADAAQAAAABAAAAJAAAAABBU0NJSQAAAFNjcmVlbnNob3SHQ+rGAAAACXBIWXMAABYlAAAWJQFJUiTwAAAB1GlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyI+CiAgICAgICAgIDxleGlmOlBpeGVsWURpbWVuc2lvbj4zNjwvZXhpZjpQaXhlbFlEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOlBpeGVsWERpbWVuc2lvbj41MjwvZXhpZjpQaXhlbFhEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOlVzZXJDb21tZW50PlNjcmVlbnNob3Q8L2V4aWY6VXNlckNvbW1lbnQ+CiAgICAgIDwvcmRmOkRlc2NyaXB0aW9uPgogICA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgr5FDsvAAAAHGlET1QAAAACAAAAAAAAABIAAAAoAAAAEgAAABIAAAHM67+vYAAAAZhJREFUWAnsVb2KwkAQHks7BRVR4jsIYpUiWKYRkTxACkuxEysVi4CFjU8RH8DWN7BOZZEiCIYQEPwDw5y73MZsyF57yZ0DYXfm2wzzzWy+5PBl8Ics9yGU8ml+JpTyAUGmJnS73cB1XWg0GuK+ElHIgu12O5QkCYvFIuq6LiwZhEjKgF6vR8kQQuSxLCuxwswQGg6HHKHT6ZRtQrZt42AwwE6ng5vNJpEMCWZKFMRK8Eb+L6Hz+Qz7/R4cxwHP86BcLkO9Xod2uw35fP7dotiOyOzxeKTRWq0GpVIpduLtkrwkP7FqtQqVSiUEL5cLHA4H6hcKBbF0Cy/jN+D7Po7HY+6DZEpDViKl8/kcr9drYqrFYhG+u1wuE8+w4Gq1Cs/OZjMWput2uw2xfr/PYVHnR5V7dQRbrVaYKEokvlcUBV+TiOam+9QQejweKMsyR4aQm06nVGUmkwk2m00O73a7GAQBRyo1hNbrNVesYRhcocwZjUbcOdM0GUTX1BCKdl/TNHw+n1yhzLnf7/TfwK6gqqoM+hVCXwAAAP///HYhaQAAAo9JREFU7VZPqHFBFJ9vY2XBVllirZTNy8IKZWVhQULZPgs7C2ShFAspewsLsiB/SmxISpSkyFKRIiR/Cum+O77u+e747vO8l2Lxpm5zzpzfnHN+Z+aeexHFMfr9PiUUCuEZDAYcqH9LtVoNsHjfbDYDo9/vB1swGIR1LiEcDgPW6/USkEKhADaDwUDY2ApiK4xcLBZhM07weDwyJs4ZE2AXoNVqAe4lCMXjcUjw7e0NkrsliMVi2IMLwoyXIBSNRiE5o9HI5HZzxsSZU0omk4B9CUKJRAKSk8vlkNxnwvl8BjwmVS6XAfodQqFQCPw89B3CCTHVxvNut4MEuYTRaETgO50OwNiEPB4PrHMJLpcL/DyU0Hg8BseYUKPR4IoPa9lslsBvNhuwxWIxsNlsNljnEnQ6HWAfSggH02g04Bxfu/V6zZUDNZ1OKalUClir1UrgqtUq2HDj2O/3hJ1R2u024HARH04ok8kQAUwmE7VarZj4lxm3azZxnEi9Xicw8/mc8ON2u6nT6URgut0upVAoCNxPCf3BntEnw2KxoHw+T1iVSiWSSCSo1+shOhHCZrfbEf1iE2tY0Wq1qNlswrpMJkMqlQrxeDw0HA5RpVIBGyO8v78jn8/HqIj+FCCz2XzR1Wo1SqfTYCMEolRXyna7pWhSROXwKXA9TqeTOhwOVx7+qovF4r8TuPaB234gEADfPz0hzj8Fdla4JadSKYquCgRjJ6PX66lcLsfewinjRuNwOIj3jfGDux++zpFIBGLg7sgepVIJbLe+jTevHHGUtLJcLhHdBBDdxhGfz0cikQgJBIJr2Jf6ZDK5+KEJIbpRXK7el5vuBHyL0J0+nwr7JfTU8t8R/PeE7ijSUyEf9xqMU4B4MecAAAAASUVORK5CYII=",
            "hashes": {
                "SHA-256": "effb46bba03f6c8aea5c653f9cf984f170dcdd3bbbe2ff6843c3e5da0e698766"
            }
        },
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--6ce09d9c-0ad3-5ebf-900c-e3cb288955b5",
            "hashes": {
                "SHA-256": "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db"
            },
            "name": "tabby_pics.zip",
            "magic_number_hex": "504B0304"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "email",
        "meta-category": "network",
        "template_uuid": "a0c666e0-fc65-4be8-b48f-3423d788b552",
        "description": "Email object describing an email with meta-information",
        "template_version": "19",
        "uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
        "ObjectReference": [
            {
                "uuid": "e18de3d0-05fe-5f18-8f0c-11f262a2b059",
                "object_uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
                "referenced_uuid": "4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
                "relationship_type": "contains"
            },
            {
                "uuid": "c84f8393-c4b4-54f6-8f7b-1ca2113b0b6e",
                "object_uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
                "referenced_uuid": "6ce09d9c-0ad3-5ebf-900c-e3cb288955b5",
                "relationship_type": "contains"
            }
        ],
        "Attribute": [
            {
                "uuid": "dd4b1cb4-3b71-543c-83e9-0891a4ed36f3",
                "object_relation": "send-date",
                "value": "2016-06-19T14:20:40+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "72c80709-c538-567e-909d-3488da9dcd4b",
                "object_relation": "header",
                "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)",
                "type": "email-header",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "57544875-2322-50cd-8e39-337b49c4c347",
                "object_relation": "subject",
                "value": "Check out this picture of a cat!",
                "type": "email-subject",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "2c630348-327c-5745-a897-cf1deb305808",
                "object_relation": "x-mailer",
                "value": "Mutt/1.5.23",
                "type": "email-x-mailer",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "a917e587-ec10-52f3-8887-d5d0ecbc49e6",
                "object_relation": "received-header-ip",
                "value": "198.51.100.3",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "89d84514-007f-5e66-811f-273f736632d6",
                "object_relation": "from",
                "value": "jdoe@example.com",
                "type": "email-src",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "d0673a67-249e-5281-880c-a3e9aa582d91",
                "object_relation": "from-display-name",
                "value": "John Doe",
                "type": "email-src-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "64bcae60-89d4-567b-bba7-7c29735110ff",
                "object_relation": "to",
                "value": "bob@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "a6ce5208-183a-5aec-bd9f-90f1d63369ac",
                "object_relation": "to-display-name",
                "value": "Bob Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "95927acc-288c-581c-ab7b-c2f39c0814f4",
                "object_relation": "cc",
                "value": "mary@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "8b9d2bbd-068a-54c1-a79b-5af740e90bb9",
                "object_relation": "cc-display-name",
                "value": "Mary Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "785375b9-8d97-595a-a4b3-9b8ccfa65de7",
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
  - STIX - Observable
    ```json
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--cf9b4b7f-14c8-5955-8065-020e0316b559",
        "is_multipart": true,
        "date": "2016-06-19T14:20:40Z",
        "content_type": "multipart/mixed",
        "from_ref": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
        "to_refs": [
            "email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868"
        ],
        "cc_refs": [
            "email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194"
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
                "body_raw_ref": "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
                "content_type": "image/png",
                "content_disposition": "attachment; filename=\"tabby.png\""
            },
            {
                "body_raw_ref": "file--6ce09d9c-0ad3-5ebf-900c-e3cb288955b5",
                "content_type": "application/zip",
                "content_disposition": "attachment; filename=\"tabby_pics.zip\""
            }
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
        "uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
        "ObjectReference": [
            {
                "uuid": "e18de3d0-05fe-5f18-8f0c-11f262a2b059",
                "object_uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
                "referenced_uuid": "4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5",
                "relationship_type": "contains"
            },
            {
                "uuid": "c84f8393-c4b4-54f6-8f7b-1ca2113b0b6e",
                "object_uuid": "cf9b4b7f-14c8-5955-8065-020e0316b559",
                "referenced_uuid": "6ce09d9c-0ad3-5ebf-900c-e3cb288955b5",
                "relationship_type": "contains"
            }
        ],
        "Attribute": [
            {
                "uuid": "dd4b1cb4-3b71-543c-83e9-0891a4ed36f3",
                "object_relation": "send-date",
                "value": "2016-06-19T14:20:40+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "72c80709-c538-567e-909d-3488da9dcd4b",
                "object_relation": "header",
                "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)",
                "type": "email-header",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "57544875-2322-50cd-8e39-337b49c4c347",
                "object_relation": "subject",
                "value": "Check out this picture of a cat!",
                "type": "email-subject",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "2c630348-327c-5745-a897-cf1deb305808",
                "object_relation": "x-mailer",
                "value": "Mutt/1.5.23",
                "type": "email-x-mailer",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "a917e587-ec10-52f3-8887-d5d0ecbc49e6",
                "object_relation": "received-header-ip",
                "value": "198.51.100.3",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "89d84514-007f-5e66-811f-273f736632d6",
                "object_relation": "from",
                "value": "jdoe@example.com",
                "type": "email-src",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "d0673a67-249e-5281-880c-a3e9aa582d91",
                "object_relation": "from-display-name",
                "value": "John Doe",
                "type": "email-src-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "64bcae60-89d4-567b-bba7-7c29735110ff",
                "object_relation": "to",
                "value": "bob@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "a6ce5208-183a-5aec-bd9f-90f1d63369ac",
                "object_relation": "to-display-name",
                "value": "Bob Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "95927acc-288c-581c-ab7b-c2f39c0814f4",
                "object_relation": "cc",
                "value": "mary@example.com",
                "type": "email-dst",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "8b9d2bbd-068a-54c1-a79b-5af740e90bb9",
                "object_relation": "cc-display-name",
                "value": "Mary Smith",
                "type": "email-dst-display-name",
                "category": "Payload delivery",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "785375b9-8d97-595a-a4b3-9b8ccfa65de7",
                "object_relation": "email-body",
                "value": "Cats are funny!",
                "type": "email-body",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- file
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive file indicator",
        "pattern": "[file:hashes.'MD5' = '8764605c6f388c89096b534d33565802' AND file:hashes.'SHA-1' = '46aba99aa7158e4609aaa72b50990842fd22ae86' AND file:hashes.'SHA-256' = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b' AND file:size = 35 AND file:name = 'oui' AND file:name_enc = 'UTF-8']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
            "payload_bin": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
            "hashes": {
                "MD5": "8764605c6f388c89096b534d33565802"
            },
            "encryption_algorithm": "mime-type-indicated",
            "decryption_key": "infected"
        }
    ]
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
        "ObjectReference": [
            {
                "uuid": "6f8125af-c9b5-5a83-bcee-5c39ac75d79d",
                "object_uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "referenced_uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                "relationship_type": "contained-in"
            }
        ],
        "Attribute": [
            {
                "uuid": "8975d5fe-3c7a-5ca7-8e6e-86e6b02e6c7f",
                "object_relation": "md5",
                "value": "8764605c6f388c89096b534d33565802",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "d37dff2b-7f1e-5ca9-8179-77315b8d214c",
                "object_relation": "sha1",
                "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "60b6e27c-5990-547f-bb6a-7433d955e572",
                "object_relation": "sha256",
                "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "aac0d199-4996-57af-bd63-da6090fe6aca",
                "object_relation": "filename",
                "value": "oui",
                "type": "filename",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "e79dfdc8-e217-596d-bb4f-2e701384451d",
                "object_relation": "file-encoding",
                "value": "UTF-8",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "139308db-d168-5daa-89de-26c89a1966f9",
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
        "comment": "Observed Data ID: observed-data--5e384ae7-672c-4250-9cda-3b4da964451a - Observed Data ID: observed-data--1a165e68-ea72-44e6-b821-3b88f2cc46d8"
    }
    ```
  - STIX - Observable
    ```json
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
        "parent_directory_ref": "directory--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "ObjectReference": [
            {
                "uuid": "6f8125af-c9b5-5a83-bcee-5c39ac75d79d",
                "object_uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "referenced_uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                "relationship_type": "contained-in"
            }
        ],
        "Attribute": [
            {
                "uuid": "8975d5fe-3c7a-5ca7-8e6e-86e6b02e6c7f",
                "object_relation": "md5",
                "value": "8764605c6f388c89096b534d33565802",
                "type": "md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "d37dff2b-7f1e-5ca9-8179-77315b8d214c",
                "object_relation": "sha1",
                "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
                "type": "sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "60b6e27c-5990-547f-bb6a-7433d955e572",
                "object_relation": "sha256",
                "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
                "type": "sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Payload delivery"
            },
            {
                "uuid": "aac0d199-4996-57af-bd63-da6090fe6aca",
                "object_relation": "filename",
                "value": "oui",
                "type": "filename",
                "category": "Payload delivery",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "e79dfdc8-e217-596d-bb4f-2e701384451d",
                "object_relation": "file-encoding",
                "value": "UTF-8",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "139308db-d168-5daa-89de-26c89a1966f9",
                "object_relation": "size-in-bytes",
                "value": "35",
                "type": "size-in-bytes",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- geolocation
  - STIX - Location
    ```json
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--e8f1c2a3-4b5d-4e6f-9a8b-7c6d5e4f3a2b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-01-25T10:18:28.125Z",
        "modified": "2024-01-25T10:18:29.125Z",
        "name": "Paris",
        "latitude": 48.8566,
        "longitude": 2.3522,
        "precision": 1000.0,
        "region": "western-europe",
        "country": "FR",
        "city": "Paris",
        "street_address": "5 Rue de la Paix",
        "postal_code": "75000"
    }
    ```
  - MISP
    ```json
    {
        "name": "geolocation",
        "meta-category": "misc",
        "template_uuid": "cd6f2238-ba55-4888-82c4-104e6e1acf21",
        "description": "An object to describe a geographic location.",
        "template_version": "8",
        "uuid": "e8f1c2a3-4b5d-4e6f-9a8b-7c6d5e4f3a2b",
        "Attribute": [
            {
                "uuid": "7c9ad6a8-65ce-5832-9046-9c7d3257f795",
                "object_relation": "city",
                "value": "Paris",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "6cf21704-ef2f-5906-b240-94f732d40f12",
                "object_relation": "countrycode",
                "value": "FR",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "d4fa159a-3471-5475-80fc-974dd12cd26e",
                "object_relation": "latitude",
                "value": 48.8566,
                "type": "float",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "269701b6-dcc3-5975-aa1e-142bc4be2925",
                "object_relation": "longitude",
                "value": 2.3522,
                "type": "float",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a5a38d12-fd81-5f6f-80f5-ceeb4efa5ce6",
                "object_relation": "zipcode",
                "value": "75000",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "cd1fc04a-1ded-5fca-8db7-056a8da8947c",
                "object_relation": "region",
                "value": "western-europe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "414b2e2f-4c1d-5fd4-9de1-5c5338305ae1",
                "object_relation": "address",
                "value": "5 Rue de la Paix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4a8f404e-8f21-5217-8ae2-d0961d87c167",
                "object_relation": "accuracy-radius",
                "value": 1.0,
                "type": "float",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0",
        "timestamp": "1706177909"
    }
    ```

- identity
  - STIX - Identity
    ```json
    {
        "type": "identity",
        "spec_version": "2.1",
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

- malware-analysis
  - STIX - Malware Analysis
    ```json
    {
        "type": "malware-analysis",
        "spec_version": "2.1",
        "id": "malware-analysis--f44f7eb8-0c10-4bb3-b59e-6b1d8a3f9c41",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-01-25T10:18:28.125Z",
        "modified": "2024-01-25T10:18:29.125Z",
        "product": "VirusTotal",
        "version": "3.0",
        "configuration_version": "1.2.0",
        "modules": [
            "static_analysis"
        ],
        "analysis_engine_version": "5.6.0",
        "analysis_definition_version": "2024-01-20",
        "submitted": "2024-01-25T10:00:00Z",
        "analysis_started": "2024-01-25T10:05:00Z",
        "analysis_ended": "2024-01-25T10:15:00Z",
        "result_name": "Trojan.Generic",
        "result": "malicious"
    }
    ```
  - MISP
    ```json
    {
        "name": "malware-analysis",
        "meta-category": "misc",
        "template_uuid": "8229ee82-7218-4ff5-9eac-57961a6f0288",
        "description": "Malware Analysis captures the metadata and results of a particular static or dynamic analysis performed on a malware instance or family.",
        "template_version": "1",
        "uuid": "f44f7eb8-0c10-4bb3-b59e-6b1d8a3f9c41",
        "Attribute": [
            {
                "uuid": "81e8d790-c29f-5af8-892c-a0eb0b7cab74",
                "object_relation": "analysis_definition_version",
                "value": "2024-01-20",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "f0326f10-05d5-514d-affc-e05f1fa94368",
                "object_relation": "end_time",
                "value": "2024-01-25T10:15:00+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "661f0206-b847-566b-8664-0a2fb66a3604",
                "object_relation": "analysis_engine_version",
                "value": "5.6.0",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e10c6883-705d-57b8-9522-edbae5bf00e9",
                "object_relation": "start_time",
                "value": "2024-01-25T10:05:00+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b8f9f1e8-b723-5ec2-b6c0-161aa987759d",
                "object_relation": "configuration_version",
                "value": "1.2.0",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "0e3ac463-17a9-5c01-9167-64d5dca29545",
                "object_relation": "module",
                "value": "static_analysis",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "c88e5093-fbc9-5793-aeee-f494aed2d1c0",
                "object_relation": "product",
                "value": "VirusTotal",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4a43fec6-6db5-5ba6-8da9-eb1cb072487f",
                "object_relation": "result",
                "value": "malicious",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "cb14f158-8775-514b-a2c0-d3054ca89a89",
                "object_relation": "result_name",
                "value": "Trojan.Generic",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "6b657a2e-9a33-5449-bbfb-d31f92243cec",
                "object_relation": "submitted_time",
                "value": "2024-01-25T10:00:00+00:00",
                "type": "datetime",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e6b2f43a-f768-5035-b7d8-1fb29ed077c3",
                "object_relation": "version",
                "value": "3.0",
                "type": "text",
                "disable_correlation": true,
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
        "spec_version": "2.1",
        "id": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:src_ref.value = '1.2.3.4' AND network-traffic:dst_ref.value = '5.6.7.8' AND network-traffic:dst_port = 80 AND network-traffic:src_port = 8080 AND network-traffic:protocols[0] = 'tcp' AND network-traffic:extensions.'socket-ext'.address_family = 'AF_INET' AND network-traffic:extensions.'socket-ext'.socket_type = 'SOCK_RAW' AND network-traffic:extensions.'socket-ext'.is_listening = true]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z"
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
        "spec_version": "2.1",
        "id": "indicator--f6a7b8c9-d0e1-4f2a-bb4c-5d6e7f809102",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive network traffic indicator",
        "description": "Network traffic indicator covering src/dst refs, ports, protocols, and byte counts.",
        "pattern": "[network-traffic:src_ref.value = '203.0.113.1' AND network-traffic:dst_ref.value = '198.51.100.34' AND network-traffic:src_port = 2487 AND network-traffic:dst_port = 53 AND network-traffic:protocols[0] = 'ipv4' AND network-traffic:protocols[1] = 'udp' AND network-traffic:protocols[2] = 'dns' AND network-traffic:src_byte_count = 35779 AND network-traffic:dst_byte_count = 935750]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3cd23a7b-a099-49df-b397-189018311d4e",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-11-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-11-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
                "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
                "ipv4-addr--ffe65ce3-bf2a-577c-bb7e-947d39198637",
                "network-traffic--ac267abc-1a41-536d-8e8d-98458d9bf491",
                "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3"
            ]
        },
        {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--ac267abc-1a41-536d-8e8d-98458d9bf491",
            "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
            "dst_ref": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
            "src_port": 2487,
            "dst_port": 1723,
            "protocols": [
                "ipv4",
                "pptp"
            ],
            "src_byte_count": 35779,
            "dst_byte_count": 935750,
            "encapsulates_refs": [
                "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3"
            ]
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
            "value": "198.51.100.2"
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
            "value": "203.0.113.1"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "network-traffic",
        "meta-category": "network",
        "template_uuid": "16290b18-9af5-4a43-b195-75fe1eef0c35",
        "description": "Generic network traffic that originates from a source and is addressed to a destination.",
        "template_version": "1",
        "uuid": "ac267abc-1a41-536d-8e8d-98458d9bf491",
        "ObjectReference": [
            {
                "uuid": "a1635e4d-35fd-523b-8fd3-40f3f821baf9",
                "object_uuid": "ac267abc-1a41-536d-8e8d-98458d9bf491",
                "referenced_uuid": "53e0bf48-2eee-5c03-8bde-ed7049d2c0a3",
                "relationship_type": "encapsulates"
            }
        ],
        "Attribute": [
            {
                "uuid": "d141bf7b-55a4-521e-8ede-5c05dfb29019",
                "object_relation": "src_port",
                "value": "2487",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "6877489f-1151-5b15-a410-80b271b40917",
                "object_relation": "dst_port",
                "value": "1723",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "ea970649-3dc0-5b51-a8da-6a0ebcc50191",
                "object_relation": "src_byte_count",
                "value": "35779",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "7fe6e0c1-f202-5ce9-ab78-4dd52a501870",
                "object_relation": "dst_byte_count",
                "value": "935750",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "599d0f6b-a300-5cc4-b3f9-62ef28324e2f",
                "object_relation": "protocol",
                "value": "IPV4",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "aa8b3868-ae70-5b21-b86f-31fd6f700289",
                "object_relation": "protocol",
                "value": "PPTP",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8026bed7-ec03-556b-8cbb-4d2656cf2b71",
                "object_relation": "src_ip",
                "value": "198.51.100.2",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "976c07df-553e-5dde-838f-ca11b3bfa9a8",
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
  - STIX - Observable
    ```json
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--b4a8c150-e214-57a3-9017-e85dfa345f46",
        "src_ref": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb7",
        "dst_ref": "ipv4-addr--f2d3c796-6c1a-5c4f-8516-d4db54727f89",
        "src_port": 2487,
        "dst_port": 53,
        "protocols": [
            "ipv4",
            "udp",
            "dns"
        ],
        "src_byte_count": 35779,
        "dst_byte_count": 935750,
        "src_payload_ref": "artifact--5e384ae7-672c-4250-9cda-3b4da964451a",
        "encapsulates_refs": [
            "network-traffic--65a6016d-a91c-5781-baad-178cd55f01d4"
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
        "uuid": "b4a8c150-e214-57a3-9017-e85dfa345f46",
        "ObjectReference": [
            {
                "uuid": "190e3170-7296-56ab-8fe3-c936d5301728",
                "object_uuid": "b4a8c150-e214-57a3-9017-e85dfa345f46",
                "referenced_uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "relationship_type": "source-sent"
            },
            {
                "uuid": "12f432ec-a088-570b-bc3e-b58398f01e3b",
                "object_uuid": "b4a8c150-e214-57a3-9017-e85dfa345f46",
                "referenced_uuid": "65a6016d-a91c-5781-baad-178cd55f01d4",
                "relationship_type": "encapsulates"
            }
        ],
        "Attribute": [
            {
                "uuid": "4960ceb5-5650-5031-88be-25a267f68358",
                "object_relation": "src_port",
                "value": "2487",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "d604a888-30c0-5556-a946-d4e84344d6f2",
                "object_relation": "dst_port",
                "value": "53",
                "type": "port",
                "category": "Network activity",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "7947fba5-6693-5367-bc67-8511c11d4559",
                "object_relation": "src_byte_count",
                "value": "35779",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "bf39e42e-4db8-5a1a-82c7-659b281eaaf2",
                "object_relation": "dst_byte_count",
                "value": "935750",
                "type": "size-in-bytes",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a3854301-2649-5eee-8cc1-e8b569c46159",
                "object_relation": "protocol",
                "value": "IPV4",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ceb5d302-f8ce-599c-9fec-d7ddf70a482e",
                "object_relation": "protocol",
                "value": "UDP",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a3d02a0e-8471-5e93-a901-b1049b9ff98c",
                "object_relation": "protocol",
                "value": "DNS",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "7b003f67-8824-5f85-a4d5-7e099efc9bca",
                "object_relation": "src_ip",
                "value": "203.0.113.1",
                "type": "ip-src",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "38ecac0d-519d-56ba-8900-0dac93adcfee",
                "object_relation": "dst_ip",
                "value": "198.51.100.34",
                "type": "ip-dst",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- process
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive process indicator",
        "description": "Process indicator covering pid, name, cwd, created_time, command_line, and image_ref.",
        "pattern": "[process:pid = 2107 AND process:name = 'Friends_From_H' AND process:cwd = '/home/viktor' AND process:created_time = '2017-05-01T08:00:00Z' AND process:command_line = 'grep -nrG iglocska ${HOME}/friends.txt']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "process--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0"
            ]
        },
        {
            "type": "process",
            "spec_version": "2.1",
            "id": "process--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
            "pid": 666,
            "command_line": "rm -rf *",
            "name": "SatanProcess"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "process",
        "meta-category": "misc",
        "template_uuid": "02aeef94-ac23-455c-addb-731757ceafb5",
        "description": "Object describing a system process.",
        "template_version": "10",
        "uuid": "28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "Attribute": [
            {
                "uuid": "85fbd20d-dafc-59e5-aa5a-ac9bf693e348",
                "object_relation": "command-line",
                "value": "rm -rf *",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "23f80906-9216-5cc6-9e7f-2dab54e8464a",
                "object_relation": "name",
                "value": "SatanProcess",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "813da7c3-6e1a-5817-a026-feaa815c58d8",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_hidden": true,
        "pid": 2510,
        "image_ref": "file--43fdb7b9-a771-4b10-ab74-2bac893daf0d",
        "parent_ref": "process--5e384ae7-672c-4250-9cda-3b4da964451a",
        "child_refs": [
            "process--f93cb275-0366-4ecc-abf0-a17928d1e177"
        ],
        "name": "TestProcess"
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
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "ObjectReference": [
            {
                "uuid": "0fbe865c-7640-5c93-baa5-178e30725792",
                "object_uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "referenced_uuid": "43fdb7b9-a771-4b10-ab74-2bac893daf0d",
                "relationship_type": "executes"
            },
            {
                "uuid": "3b9535ef-87ea-5d90-8d1c-586bade04768",
                "object_uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "referenced_uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
                "relationship_type": "child-of"
            },
            {
                "uuid": "332e8042-c298-517c-af1f-66cbc331910e",
                "object_uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "referenced_uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
                "relationship_type": "parent-of"
            }
        ],
        "Attribute": [
            {
                "uuid": "2eecf9a3-771c-51c8-aaee-518048a5791e",
                "object_relation": "hidden",
                "value": true,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8df7898c-0022-5e4e-8f5c-496b1b484f38",
                "object_relation": "name",
                "value": "TestProcess",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4e5312be-0ec5-5883-ac6c-a46866e01a6c",
                "object_relation": "pid",
                "value": "2510",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- registry-key
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[windows-registry-key:key = 'hkey_local_machine\\\\system\\\\foo\\\\fortytwo' AND windows-registry-key:modified_time = '2018-10-25T16:22:00Z' AND windows-registry-key:values[0].name = 'FortyTwoFoo' AND windows-registry-key:values[0].data = '%DATA%\\\\42' AND windows-registry-key:values[0].data_type = 'REG_QWORD']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z"
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
        "timestamp": "1603642920"
    }
    ```
  - STIX - Observed Data
    ```json
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "windows-registry-key--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
                "user-account--5e384ae7-672c-4250-9cda-3b4da964451a"
            ]
        },
        {
            "type": "windows-registry-key",
            "spec_version": "2.1",
            "id": "windows-registry-key--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
            "key": "hkey_local_machine\\system\\foo\\fortytwo",
            "values": [
                {
                    "name": "FortyTwoFoo",
                    "data": "%DATA%\\42",
                    "data_type": "REG_QWORD"
                }
            ],
            "modified_time": "2020-10-25T16:22:00Z",
            "creator_user_ref": "user-account--5e384ae7-672c-4250-9cda-3b4da964451a"
        }
    ]
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
                "uuid": "4d714fdb-5565-5d31-b311-36d25cb7c889",
                "object_relation": "key",
                "value": "hkey_local_machine\\system\\foo\\fortytwo",
                "type": "regkey",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "1f2c1a24-4c5c-56c9-89ba-252e0c1073ed",
                "object_relation": "last-modified",
                "value": "2020-10-25T16:22:00+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "e20515d6-4ead-5c98-880f-06686c41ad47",
                "object_relation": "data",
                "value": "%DATA%\\42",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "0a249bc4-c55d-5378-bf57-8b0c90d6ec07",
                "object_relation": "data-type",
                "value": "REG_QWORD",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "eb724060-cdda-531c-b3c4-412c7c33f764",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--28b2fff7-ca78-483b-9c4f-6f684ee7cdd0",
        "key": "hkey_local_machine\\system\\foo\\fortytwo",
        "values": [
            {
                "name": "FortyTwoFoo",
                "data": "%DATA%\\42",
                "data_type": "REG_QWORD"
            }
        ],
        "modified_time": "2020-10-25T16:22:00Z",
        "creator_user_ref": "user-account--5e384ae7-672c-4250-9cda-3b4da964451a"
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
                "uuid": "4d714fdb-5565-5d31-b311-36d25cb7c889",
                "object_relation": "key",
                "value": "hkey_local_machine\\system\\foo\\fortytwo",
                "type": "regkey",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "1f2c1a24-4c5c-56c9-89ba-252e0c1073ed",
                "object_relation": "last-modified",
                "value": "2020-10-25T16:22:00+00:00",
                "type": "datetime",
                "category": "Other",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "e20515d6-4ead-5c98-880f-06686c41ad47",
                "object_relation": "data",
                "value": "%DATA%\\42",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            },
            {
                "uuid": "0a249bc4-c55d-5378-bf57-8b0c90d6ec07",
                "object_relation": "data-type",
                "value": "REG_QWORD",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": true,
                "to_ids": false
            },
            {
                "uuid": "eb724060-cdda-531c-b3c4-412c7c33f764",
                "object_relation": "name",
                "value": "FortyTwoFoo",
                "type": "text",
                "category": "Persistence mechanism",
                "disable_correlation": false,
                "to_ids": false
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- software
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--c9d0e1f2-a3b4-4c5d-ae7f-809102132435",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive software indicator",
        "description": "Software indicator covering name, cpe, swid, languages, vendor, and version.",
        "pattern": "[software:name = 'Acrobat X Pro' AND software:cpe = 'cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*' AND software:swid = '<?xml version=\\'1.0\\' encoding=\\'utf-8\\'?><swid:software_identification_tag xsi:schemaLocation=\\'https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd\\'xmlns:swid=\\'https://standards.iso.org/iso/19770/-2/2008/schema.xsd\\' xmlns:xsi=\\'https://www.w3.org/2001/XMLSchema-instance\\'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>' AND software:languages[0] = 'C#' AND software:vendor = 'Adobe Inc.' AND software:version = '10.0']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "software--f93cb275-0366-4ecc-abf0-a17928d1e177"
            ]
        },
        {
            "type": "software",
            "spec_version": "2.1",
            "id": "software--f93cb275-0366-4ecc-abf0-a17928d1e177",
            "name": "Acrobat X Pro",
            "cpe": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
            "swid": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>",
            "languages": [
                "C#",
                "Javascript",
                "Postscript"
            ],
            "vendor": "Adobe Inc.",
            "version": "10.0"
        }
    ]
    ```
  - MISP
    ```json
    {
        "name": "software",
        "meta-category": "misc",
        "template_uuid": "b1b5dc0e-73fe-443c-8d9d-0e208de3951e",
        "description": "The Software object represents high-level properties associated with software, including software products. STIX 2.1 - 6.14",
        "template_version": "1",
        "uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
        "Attribute": [
            {
                "uuid": "b151eab8-cd25-5ee9-9117-ac52876908e4",
                "object_relation": "cpe",
                "value": "cpe:2.3:a:adobe:acrobat:10.0:-:pro:*:*:*:*:*",
                "type": "cpe",
                "disable_correlation": false,
                "to_ids": false,
                "category": "External analysis"
            },
            {
                "uuid": "3fedf0b3-5356-5cea-92cd-cee1083d4d7f",
                "object_relation": "language",
                "value": "C#",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "55289bca-b7df-582a-874a-3e08528b23ba",
                "object_relation": "language",
                "value": "Javascript",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b0857b45-88eb-506d-a6f6-5b211bf44d83",
                "object_relation": "language",
                "value": "Postscript",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "745f9b59-4038-5ac3-9474-5667b4467716",
                "object_relation": "name",
                "value": "Acrobat X Pro",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "f83f48e9-3d08-5631-97ea-9431cc237c03",
                "object_relation": "swid",
                "value": "<?xml version='1.0' encoding='utf-8'?><swid:software_identification_tag xsi:schemaLocation='https://standards.iso.org/iso/19770/-2/2008/schema.xsd software_identification_tag.xsd'xmlns:swid='https://standards.iso.org/iso/19770/-2/2008/schema.xsd' xmlns:xsi='https://www.w3.org/2001/XMLSchema-instance'><!--Mandatory Identity elements --><swid:entitlement_required_indicator>true</swid:entitlement_required_indicator><swid:product_title>Acrobat X Pro</swid:product_title><swid:product_version><swid:name>10.0</swid:name><swid:numeric><swid:major>10</swid:major><swid:minor>0</swid:minor><swid:build>0</swid:build><swid:review>0</swid:review></swid:numeric></swid:product_version><swid:software_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_creator><swid:software_licensor><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:software_licensor><swid:software_id><swid:unique_id>AcrobatPro-AS1-Win-GM-MUL</swid:unique_id><swid:tag_creator_regid>regid.1986-12.com.adobe</swid:tag_creator_regid></swid:software_id><swid:tag_creator><swid:name>Adobe Inc.</swid:name><swid:regid>regid.1986-12.com.adobe</swid:regid></swid:tag_creator><!--Optional Identity elements --><swid:license_linkage><swid:activation_status>unlicensed</swid:activation_status><swid:channel_type>VOLUME</swid:channel_type><swid:customer_type>VOLUME</swid:customer_type></swid:license_linkage><swid:serial_number>970787034620329571838915</swid:serial_number></swid:software_identification_tag>",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "1dabb09b-2ac0-5917-942f-b43701f8aea9",
                "object_relation": "vendor",
                "value": "Adobe Inc.",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e66d89f4-3af3-5732-a8c5-d2c5fe11ef7f",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--5e384ae7-672c-4250-9cda-3b4da964451a",
        "name": "misp-stix",
        "languages": [
            "Python"
        ],
        "vendor": "CIRCL",
        "version": "2.4.183"
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
        "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
        "Attribute": [
            {
                "uuid": "4a8235d3-ff5e-5d29-87e9-8b1391c29e05",
                "object_relation": "language",
                "value": "Python",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b1217423-4a0e-5276-b448-787c3100bc47",
                "object_relation": "name",
                "value": "misp-stix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "dd104b57-ffd1-5740-95a5-57ae03687ed1",
                "object_relation": "vendor",
                "value": "CIRCL",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "4a3c1a21-f2f1-5b37-8b40-5d321256e74c",
                "object_relation": "version",
                "value": "2.4.183",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- user-account
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--d0e1f2a3-b4c5-4d6e-bf80-910213243546",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive user account indicator",
        "description": "User account indicator covering user_id, account_login, account_type, display_name, booleans, and timestamps.",
        "pattern": "[user-account:user_id = '1001' AND user-account:account_login = 'jdoe' AND user-account:account_type = 'unix' AND user-account:display_name = 'John Doe' AND user-account:is_service_account = false AND user-account:is_privileged = false AND user-account:can_escalate_privs = true AND user-account:account_created = '2016-01-20T12:31:12Z' AND user-account:credential_last_changed = '2016-01-20T14:27:43Z' AND user-account:account_first_login = '2016-01-20T14:26:07Z' AND user-account:account_last_login = '2016-07-22T16:08:28Z']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
            ]
        },
        {
            "type": "user-account",
            "spec_version": "2.1",
            "id": "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
    ]
    ```
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "template_uuid": "49606b06-22f0-4ac8-8eee-2f12ad46f3d3",
        "description": "User-account object, defining aspects of user identification, authentication, privileges and other relevant data points.",
        "template_version": "6",
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "Attribute": [
            {
                "uuid": "18afcb74-4bf6-54b4-a3d6-f4366de68469",
                "object_relation": "username",
                "value": "jdoe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e6f96f1e-3959-5aa7-87e1-a91a307c960c",
                "object_relation": "account-type",
                "value": "unix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ce8d7e6c-41e9-5b4a-b201-8498f8a88dc6",
                "object_relation": "can_escalate_privs",
                "value": true,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "2d0ead89-e7f7-5576-bdb9-514aeee2d10e",
                "object_relation": "display-name",
                "value": "John Doe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "0348bd30-20a2-57c7-a6a9-148e98f7ee5d",
                "object_relation": "privileged",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a2f920e0-62c1-54b5-96f5-7086479d4378",
                "object_relation": "is_service_account",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "0458e09d-76b0-5521-b1bd-5c3a966ec5a6",
                "object_relation": "user-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ebf47376-5f16-5b5a-a46a-4e7039ccb796",
                "object_relation": "group-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "3c5bc629-f2c2-54a9-b6b2-7f0c26493c8f",
                "object_relation": "group",
                "value": "wheel",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "c932ca1d-7537-5e6c-b551-29c0e1648c16",
                "object_relation": "home_dir",
                "value": "/home/jdoe",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "7e3bb8e0-986d-5ebb-a500-2d62d27b4790",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": false,
        "is_privileged": false,
        "can_escalate_privs": true,
        "account_created": "2016-01-20T12:31:12Z",
        "credential_last_changed": "2016-01-20T14:27:43Z",
        "account_first_login": "2016-01-20T14:26:07Z",
        "account_last_login": "2016-07-22T16:08:28Z"
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
        "uuid": "0d5b424b-93b8-5cd8-ac36-306e1789d63c",
        "Attribute": [
            {
                "uuid": "16db0fd8-5a71-5234-8ddd-9a915c9f26d4",
                "object_relation": "username",
                "value": "jdoe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "ca9f7f34-bdb7-581f-982a-a290f4180f94",
                "object_relation": "account-type",
                "value": "unix",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9e38f0e0-0de4-54b6-b16e-1d96f61bcd33",
                "object_relation": "can_escalate_privs",
                "value": true,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "0832e790-786a-5a47-b6df-a71b13ec4816",
                "object_relation": "display-name",
                "value": "John Doe",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8d64f82d-91ef-5b1e-ad0c-232c1d90d780",
                "object_relation": "privileged",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "2c02f75a-811c-5850-91e3-d465146f2761",
                "object_relation": "is_service_account",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "d84e20e3-46fc-5d1f-9cad-829a1e733453",
                "object_relation": "user-id",
                "value": "1001",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a8b1ebfe-2f04-558f-a8f9-4bd7c8bb6029",
                "object_relation": "created",
                "value": "2016-01-20T12:31:12+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "e99d1a40-2cd1-5ef3-a9c4-2cf292c8a60c",
                "object_relation": "first_login",
                "value": "2016-01-20T14:26:07+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "161ebaa5-10ed-5fd2-b9e4-99efbc5bfdd6",
                "object_relation": "last_login",
                "value": "2016-07-22T16:08:28+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "b33742ad-25aa-50f5-bc05-9fbeb66795df",
                "object_relation": "password_last_changed",
                "value": "2016-01-20T14:27:43+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```

- x509
  - STIX - Indicator
    ```json
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--e1f2a3b4-c5d6-4e7f-8091-021324354657",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-10-25T16:22:00.000Z",
        "modified": "2024-10-25T16:22:00.000Z",
        "name": "Comprehensive X.509 certificate indicator",
        "description": "X.509 certificate indicator covering is_self_signed, hashes, version, serial_number, signature_algorithm, issuer, validity, subject, and public key fields.",
        "pattern": "[x509-certificate:is_self_signed = false AND x509-certificate:hashes.'MD5' = '219794f8f6128c731f476d11e7fa5d4f' AND x509-certificate:hashes.'SHA-1' = 'd02be9aa68a05fdf7e99899a9719f275db5e6b2f' AND x509-certificate:hashes.'SHA-256' = '0adb35fcd170c6da0e45a00c9b36533b21dc2bcf793e6facf0eb30829cbcc5fb' AND x509-certificate:version = '3' AND x509-certificate:serial_number = '00:bc:b4:e7:32:76:0e:ca:64:31:8e:17:6c:fd:4a:ef:30' AND x509-certificate:signature_algorithm = 'sha256WithRSAEncryption' AND x509-certificate:issuer = '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Code Signing CA' AND x509-certificate:validity_not_before = '2015-12-08T00:00:00Z' AND x509-certificate:validity_not_after = '2016-12-07T23:59:59Z' AND x509-certificate:subject = '/C=GB/postalCode=RG12 2LS/ST=Berkshire/L=Bracknell/street=15  Shepherds Hill/postOfficeBox=RG12 2LS/O=Network Software Ltd/CN=Network Software Ltd' AND x509-certificate:subject_public_key_algorithm = 'sha256WithRSAEncryption' AND x509-certificate:subject_public_key_modulus = '00:ae:29:f8:d7:56:2f:fd:61:40:89:6f:cc:a3:1c:e0:49:0c:21:9f:5e:60:0c:a9:dc:cf:5f:79:83:fd:12:8f:f3:fc:c1:49:a3:e2:9c:a8:e9:d2:88:44:16:bd:39:2e:23:5b:84:e9:54:70:4b:ce:e3:c2:19:fd:a4:8b:45:ca:ad:aa:08:ae:cc:ab:8f:eb:60:74:fa:e0:2b:e5:d1:7b:5d:87:43:26:71:96:d1:ec:5f:23:15:40:37:0e:cc:b1:e1:5a:57:f1:24:58:2c:d6:04:f3:8e:34:9a:ea:bb:88:d5:9b:c3:38:8d:e4:90:7b:e7:ef:89:ea:31:92:97:46:80:f9:f8:b2:78:53:19:b8:66:15:37:af:32:08:58:3f:42:1a:67:f5:9a:40:b7:25:75:dc:3c:5f:b1:7c:12:63:f8:2b:60:93:b5:04:c4:10:9c:2d:1f:aa:9f:af:b1:e9:ee:70:21:fb:7e:aa:b3:1a:8e:e4:4c:18:6e:6a:5d:c4:61:e3:bd:83:d2:af:c6:ce:bc:f8:b8:0f:db:e0:9e:ec:f4:e2:61:99:ee:81:63:d1:71:e4:a7:2b:de:5c:0a:6d:2e:33:94:50:1f:33:e9:bb:1c:eb:e6:d2:18:3d:4f:02:02:dc:30:2e:52:19:4f:9c:0d:15:9d:56:f1:cb:30:59:57' AND x509-certificate:subject_public_key_exponent = 65537]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-10-25T16:22:00Z"
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
    [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d",
            "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
            "created": "2020-10-25T16:22:00.000Z",
            "modified": "2020-10-25T16:22:00.000Z",
            "first_observed": "2020-10-25T16:22:00Z",
            "last_observed": "2020-10-25T16:22:00Z",
            "number_observed": 1,
            "object_refs": [
                "x509-certificate--f93cb275-0366-4ecc-abf0-a17928d1e177"
            ]
        },
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--f93cb275-0366-4ecc-abf0-a17928d1e177",
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
    ]
    ```
  - MISP
    ```json
    {
        "name": "x509",
        "meta-category": "network",
        "template_uuid": "d1ab756a-26b5-4349-9f43-765630f0911c",
        "description": "x509 object describing a X.509 certificate",
        "template_version": "14",
        "uuid": "f93cb275-0366-4ecc-abf0-a17928d1e177",
        "Attribute": [
            {
                "uuid": "047b7f59-108a-5810-ac1f-2fa28e79a220",
                "object_relation": "x509-fingerprint-md5",
                "value": "09716af84e900e403494c28ad8c5869c",
                "type": "x509-fingerprint-md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "020cef22-cc07-51a8-9f9f-09ce1ee3887c",
                "object_relation": "x509-fingerprint-sha1",
                "value": "1456d8a00d8be963e2224d845b12e5084ea0b707",
                "type": "x509-fingerprint-sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "5848befc-829e-58d4-9c44-70c50c712c0e",
                "object_relation": "x509-fingerprint-sha256",
                "value": "2d23636c25eb5c1b473e0ae66fdb076687b40bd080f161c79663572f171d5598",
                "type": "x509-fingerprint-sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "87030b71-c762-5a00-9769-cbbfb0bb7f37",
                "object_relation": "self_signed",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "03a9c3d6-206b-5234-bf12-7bf878704080",
                "object_relation": "issuer",
                "value": "C=US, O=thawte, Inc., CN=thawte SHA256 Code Signing CA",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "38b93c36-3bdb-5c33-961c-822835329398",
                "object_relation": "serial-number",
                "value": "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "eeda5340-e048-5d30-b9c7-00379d3a288e",
                "object_relation": "signature_algorithm",
                "value": "sha256WithRSAEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "f0edb35d-8abb-57da-9511-82dff581b3f3",
                "object_relation": "subject",
                "value": "C=GB, ST=London, L=London, O=Ziber Ltd, CN=Ziber Ltd",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "fd75fe20-f4d7-58b9-b00b-68cd200f5664",
                "object_relation": "pubkey-info-algorithm",
                "value": "rsaEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "cb9101ba-836c-5783-a9f5-055d62061dbb",
                "object_relation": "pubkey-info-exponent",
                "value": "65537",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "10e41866-3196-50ec-ac0e-1e0033565c82",
                "object_relation": "pubkey-info-modulus",
                "value": "00:e2:12:e4:5c:44:90:fa:0f:75:77:c8:88:51:21:1d:ce:b8:0e:f2:73:d5:68:79:02:50:51:5f:2c:a3:82:d1:48:60:f8:fa:c7:75:72:12:bc:b9:7c:d9:12:a8:1a:18:3a:f9:1d:a9:18:04:59:cd:8a:81:03:f7:0a:3d:22:6e:7d:63:65:d7:4d:c5:65:0e:fc:4f:97:9c:e0:3d:52:a4:d9:0b:d9:04:c3:f3:52:2a:a3:cc:e2:82:2c:2b:b8:54:1b:cc:41:2b:1b:76:d0:2a:fd:65:c4:3f:a2:4b:36:5f:5a:79:28:4b:98:1e:38:6c:b6:33:d2:3d:db:53:9c:0b:3f:2b:ab:87:2e:94:47:72:4f:27:58:8d:b0:b2:38:5f:1d:e0:67:53:6e:38:c7:ac:24:49:c9:b6:81:42:e0:06:95:26:c0:c9:bf:5e:7f:1b:92:f5:58:8e:8a:70:88:a9:e5:82:5c:5c:71:54:e0:74:1b:a9:33:1a:f2:3d:bf:9d:1b:45:1a:0e:02:d8:a3:d8:db:64:a9:f8:28:16:7f:4e:c3:ee:33:a1:be:18:72:e3:bd:79:12:54:ea:b9:77:9b:d0:d0:b0:2d:75:af:4d:47:4e:c1:16:84:a2:88:65:ef:18:ff:33:2a:ab:83:7c:43:14:ad:b8:cd:f0:b9:7c:c1:23",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "8262a412-420d-5b88-a535-4bdfb5ec5b91",
                "object_relation": "validity-not-after",
                "value": "2018-07-09T23:59:59+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "dbf695fa-3e4e-57f4-9478-0d75ca1a1ecc",
                "object_relation": "validity-not-before",
                "value": "2017-07-09T00:00:00+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "fc488390-34cd-5d00-aa66-126a86e14bfb",
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
        "timestamp": "1603642920",
        "comment": "Observed Data ID: observed-data--3451329f-2525-4bcb-9659-7bd0e6f1eb0d"
    }
    ```
  - STIX - Observable
    ```json
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_self_signed": false,
        "hashes": {
            "MD5": "a39a417abcbe62460665c9da765aefbe",
            "SHA-1": "bffc1a508d3c02d4a3f86941d3a99f7bf9ec3895",
            "SHA-256": "caf71b19bf181230a3b203a6c3beaceb4d261409a8dbeef2e1d9eb4a5e0182c6"
        },
        "version": "3",
        "serial_number": "00:bb:ae:27:7a:c3:d9:cf:3f:85:00:86:a3:14:e7:0a:d7",
        "signature_algorithm": "sha256WithRSAEncryption",
        "issuer": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Code Signing CA",
        "validity_not_before": "2017-11-12T00:00:00Z",
        "validity_not_after": "2018-09-12T23:59:59Z",
        "subject": "C=GB/postalCode=EC1V 2NX, ST=London, L=London/street=Kemp House, 160 City Road, O=CYBASICS LTD, CN=CYBASICS LTD",
        "subject_public_key_algorithm": "rsaEncryption",
        "subject_public_key_modulus": "c7:97:8a:4c:a0:6b:9c:91:d0:ed:7e:74:ca:8c:48:41:84:cf:fa:f1:07:ae:51:3f:d1:cb:3c:2e:43:1e:c3:dc:c2:e7:fa:60:cd:c7:25:2c:c4:2e:1c:e0:c2:a2:63:8b:df:f7:1a:55:c8:66:0d:eb:a9:a7:9e:f6:89:6e:ca:63:be:b8:75:18:56:6d:53:c1:8b:b4:f6:b5:04:6d:cc:0f:17:e0:b5:12:70:d6:b5:55:77:76:98:de:84:44:55:6d:5f:8a:a6:1e:a8:62:47:22:96:3d:5a:85:c9:9f:00:f3:3b:c6:ec:cb:68:ff:34:ab:73:d7:02:b6:29:aa:ff:87:1b:39:87:e5:0f:fd:f0:6a:d6:de:81:a3:e6:05:61:5d:84:6c:1f:5e:20:ae:c1:93:56:45:37:b7:c0:d6:6d:ab:27:f6:98:70:cf:a2:9b:c8:4a:04:2d:dc:01:fb:1a:f1:dc:8f:4c:31:7c:c4:71:4a:1c:d7:81:ed:1a:04:cb:4d:aa:3b:37:94:d3:7d:14:c4:4c:0e:8d:eb:75:1c:26:46:35:1c:83:2a:09:cf:41:c9:cb:c6:8c:a6:db:28:90:48:17:92:ff:70:db:5c:4f:d2:27:1a:51:2b:1f:12:f8:f6:ee:8a:88:15:fd:68:13:f0:7a:50:4f:8e:23:d5:4d:51",
        "subject_public_key_exponent": 65537
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
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "Attribute": [
            {
                "uuid": "77a3630b-bb40-5ba5-b395-be77159968fb",
                "object_relation": "x509-fingerprint-md5",
                "value": "a39a417abcbe62460665c9da765aefbe",
                "type": "x509-fingerprint-md5",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "ae35fef0-51d3-5c15-952b-914923890da9",
                "object_relation": "x509-fingerprint-sha1",
                "value": "bffc1a508d3c02d4a3f86941d3a99f7bf9ec3895",
                "type": "x509-fingerprint-sha1",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "6ed5a009-8df8-5655-9f37-d8f2a2951713",
                "object_relation": "x509-fingerprint-sha256",
                "value": "caf71b19bf181230a3b203a6c3beaceb4d261409a8dbeef2e1d9eb4a5e0182c6",
                "type": "x509-fingerprint-sha256",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Network activity"
            },
            {
                "uuid": "a36e88ec-1953-5b81-9bec-612c8b6b19ac",
                "object_relation": "self_signed",
                "value": false,
                "type": "boolean",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "744e5115-841a-5a3e-8fe6-b3e094eb6848",
                "object_relation": "issuer",
                "value": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Code Signing CA",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "c58b28ba-6c4e-5b88-9fbb-c4903fdd999e",
                "object_relation": "serial-number",
                "value": "00:bb:ae:27:7a:c3:d9:cf:3f:85:00:86:a3:14:e7:0a:d7",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "43aab15a-9288-58de-8840-5abb7f8f8dea",
                "object_relation": "signature_algorithm",
                "value": "sha256WithRSAEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "30857200-6adf-54d1-81d5-50eaa06d6e15",
                "object_relation": "subject",
                "value": "C=GB/postalCode=EC1V 2NX, ST=London, L=London/street=Kemp House, 160 City Road, O=CYBASICS LTD, CN=CYBASICS LTD",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "6b5649cb-5b5d-55d0-99d0-1e361f7ab571",
                "object_relation": "pubkey-info-algorithm",
                "value": "rsaEncryption",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a3d4c7b6-d5f0-5794-9251-bce8e96b885f",
                "object_relation": "pubkey-info-exponent",
                "value": "65537",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "10f7c210-4f48-5cda-b6a4-2241781fbd48",
                "object_relation": "pubkey-info-modulus",
                "value": "c7:97:8a:4c:a0:6b:9c:91:d0:ed:7e:74:ca:8c:48:41:84:cf:fa:f1:07:ae:51:3f:d1:cb:3c:2e:43:1e:c3:dc:c2:e7:fa:60:cd:c7:25:2c:c4:2e:1c:e0:c2:a2:63:8b:df:f7:1a:55:c8:66:0d:eb:a9:a7:9e:f6:89:6e:ca:63:be:b8:75:18:56:6d:53:c1:8b:b4:f6:b5:04:6d:cc:0f:17:e0:b5:12:70:d6:b5:55:77:76:98:de:84:44:55:6d:5f:8a:a6:1e:a8:62:47:22:96:3d:5a:85:c9:9f:00:f3:3b:c6:ec:cb:68:ff:34:ab:73:d7:02:b6:29:aa:ff:87:1b:39:87:e5:0f:fd:f0:6a:d6:de:81:a3:e6:05:61:5d:84:6c:1f:5e:20:ae:c1:93:56:45:37:b7:c0:d6:6d:ab:27:f6:98:70:cf:a2:9b:c8:4a:04:2d:dc:01:fb:1a:f1:dc:8f:4c:31:7c:c4:71:4a:1c:d7:81:ed:1a:04:cb:4d:aa:3b:37:94:d3:7d:14:c4:4c:0e:8d:eb:75:1c:26:46:35:1c:83:2a:09:cf:41:c9:cb:c6:8c:a6:db:28:90:48:17:92:ff:70:db:5c:4f:d2:27:1a:51:2b:1f:12:f8:f6:ee:8a:88:15:fd:68:13:f0:7a:50:4f:8e:23:d5:4d:51",
                "type": "text",
                "disable_correlation": false,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "9cd9873d-69cb-55cb-ba60-4ae6ddd4fe5f",
                "object_relation": "validity-not-after",
                "value": "2018-09-12T23:59:59+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "a03ce323-4747-50b9-b871-b5bbda5f9159",
                "object_relation": "validity-not-before",
                "value": "2017-11-12T00:00:00+00:00",
                "type": "datetime",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            },
            {
                "uuid": "03b6c2b2-0496-5b20-9f89-589793852d27",
                "object_relation": "version",
                "value": "3",
                "type": "text",
                "disable_correlation": true,
                "to_ids": false,
                "category": "Other"
            }
        ],
        "distribution": "5",
        "sharing_group_id": "0"
    }
    ```


## The other detailed mappings

- [External Attributes mapping](external_stix21_to_misp_attributes.md)
