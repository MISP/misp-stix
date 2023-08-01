#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from copy import deepcopy
from pathlib import Path
from stix2.parsing import dict_to_stix2

_TESTFILES_PATH = Path(__file__).parent.resolve() / 'attachment_test_files'
_ACCOUNT_INDICATOR_OBJECTS = [
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
    },
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
]
_ACCOUNT_OBSERVABLE_OBJECTS = [
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
    },
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
_ACCOUNT_WITH_ATTACHMENT_INDICATOR_OBJECTS = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5177abbd-c437-4acb-9173-eee371ad24da",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
]
_ACCOUNT_WITH_ATTACHMENT_OBSERVABLE_OBJECTS = [
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
        }
    },
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
        }
    },
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
        "x_misp_human": False,
        "x_misp_profile_photo": {
            "value": "octocat.png",
        }
    },
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
        },
        "x_misp_description": "Reddit account of the OctoCat"
    },
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
        }
    },
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
        }
    }
]
_ANDROID_APP_INDICATOR_OBJECT = {
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
_ANDROID_APP_OBSERVABLE_OBJECT = [
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
_ANNOTATION_OBJECT = [
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--eb6592bb-675c-48f3-9272-157141196b93",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "content": "Google public DNS",
        "object_refs": [
            "observed-data--5ac47edc-31e4-4402-a7b6-040d0a00020f",
            "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:name=\"annotation\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ],
        "x_misp_attachment": {
            "value": "annotation.attachment",
            "data": "OC44LjguOCBpcyB0aGUgR29vZ2xlIFB1YmxpYyBETlMgSVAgYWRkcmVzc2VzIChJUHY0KS4K"
        },
        "x_misp_type": "Executive Summary"
    },
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
        "x_misp_domain": "google.com"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "8.8.8.8"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '8.8.8.8']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_AS_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[autonomous-system:number = '174']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_AS_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"AS\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "number": 174
    }
]
_ASN_INDICATOR_OBJECT = {
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
_ASN_OBSERVABLE_OBJECT = [
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
_ATTACHMENT_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[file:name = 'attachment.test' AND file:content_ref.payload_bin = 'ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_ATTACHMENT_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"attachment\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "attachment.test",
        "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "payload_bin": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK"
    }
]
_ATTACK_PATTERN_GALAXY = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--e042a41b-5ecf-4f3a-8f1f-1b528c534772",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Test malware in various execution environments - PRE-T1134",
    "description": "ATT&CK Tactic | Malware may perform differently on different platforms and different operating systems.",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mitre-pre-attack",
            "phase_name": "test-capabilities"
        }
    ],
    "labels": [
        "misp:galaxy-name=\"Pre Attack - Attack Pattern\"",
        "misp:galaxy-type=\"mitre-pre-attack-attack-pattern\""
    ],
    "external_references": [
        {
            "source_name": "mitre-pre-attack",
            "external_id": "PRE-T1134"
        },
        {
            "source_name": "url",
            "url": "https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1134"
        }
    ]
}
_ATTACK_PATTERN_OBJECT = {
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
_ATTRIBUTE_WITH_EMBEDDED_GALAXY = [
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Access Token Manipulation - T1134",
        "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
        "labels": [
            "misp:galaxy-name=\"Attack Pattern\"",
            "misp:galaxy-type=\"mitre-attack-pattern\""
        ],
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-633"
            }
        ]
    },
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation - T1020",
        "description": "ATT&CK Mitigation | Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
        "labels": [
            "misp:galaxy-name=\"Course of Action\"",
            "misp:galaxy-type=\"mitre-course-of-action\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Domain test attribute",
        "pattern": "[domain-name:value = 'circl.lu']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT - S0017",
        "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
        "aliases": [
            "BISCUIT"
        ],
        "labels": [
            "misp:galaxy-name=\"Malware\"",
            "misp:galaxy-type=\"mitre-malware\""
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--74caa0d0-9366-4f19-94ec-1ec52a9e042e",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "indicates",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--88c41265-5fe6-4514-86a4-9f3034db4397",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "has",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294"
    }
]
_BUNDLE_WITH_INVALID_UUIDS = [
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-Project",
        "identity_class": "organization"
    },
    {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--fedcba09-8765-4321-fedc-ba0987654321",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-STIX-Converter test event",
        "context": "suspicious-activity",
        "labels": [
            "Threat-Report",
            "misp:tool=\"MISP-STIX-Converter\""
        ],
        "object_refs": [
            "attack-pattern--00000000-0000-0000-0000-000000000000",
            "course-of-action--11111111-1111-1111-1111-111111111111",
            "indicator--22222222-2222-2222-2222-222222222222",
            "malware--33333333-3333-3333-3333-333333333333",
            "relationship--74caa0d0-9366-4f19-94ec-1ec52a9e042e",
            "relationship--88c41265-5fe6-4514-86a4-9f3034db4397",
            "attack-pattern--44444444-4444-4444-4444-444444444444",
            "observed-data--55555555-5555-5555-5555-555555555555",
            "autonomous-system--55555555-5555-5555-5555-555555555555",
            "x-misp-object--66666666-6666-6666-6666-666666666666",
            "course-of-action--77777777-7777-7777-7777-777777777777",
            "indicator--88888888-8888-8888-8888-888888888888",
            "vulnerability--99999999-9999-9999-9999-999999999999",
            "relationship--6b34f83c-f1db-4f39-a813-4ac86c1f2fe6",
            "relationship--0ded93a1-38e5-4d2d-aecb-1f0e98daedb7",
            "relationship--94057569-8790-4fd7-9a05-ed0a054a2390",
            "relationship--f5134684-d988-42bc-964e-f2a4686c42a0",
            "relationship--e239566f-cfb0-437d-a4b2-0695c9ceffe7",
            "relationship--2cac5500-e293-4a61-a751-9d7ea9624692"
        ]
    },
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--00000000-0000-0000-0000-000000000000",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Access Token Manipulation - T1134",
        "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
        "labels": [
            "misp:galaxy-name=\"Attack Pattern\"",
            "misp:galaxy-type=\"mitre-attack-pattern\""
        ],
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-633"
            }
        ],
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef"
    },
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--11111111-1111-1111-1111-111111111111",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation - T1020",
        "description": "ATT&CK Mitigation | Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
        "labels": [
            "misp:galaxy-name=\"Course of Action\"",
            "misp:galaxy-type=\"mitre-course-of-action\""
        ],
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--22222222-2222-2222-2222-222222222222",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Domain test attribute",
        "pattern": "[domain-name:value = 'circl.lu']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--33333333-3333-3333-3333-333333333333",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT - S0017",
        "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
        "aliases": [
            "BISCUIT"
        ],
        "labels": [
            "misp:galaxy-name=\"Malware\"",
            "misp:galaxy-type=\"mitre-malware\""
        ],
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--74caa0d0-9366-4f19-94ec-1ec52a9e042e",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "indicates",
        "source_ref": "indicator--22222222-2222-2222-2222-222222222222",
        "target_ref": "attack-pattern--00000000-0000-0000-0000-000000000000"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--88c41265-5fe6-4514-86a4-9f3034db4397",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "has",
        "source_ref": "indicator--22222222-2222-2222-2222-222222222222",
        "target_ref": "course-of-action--11111111-1111-1111-1111-111111111111"
    },
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--44444444-4444-4444-4444-444444444444",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Buffer Overflow in Local Command-Line Utilities",
        "description": "This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root.",
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
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--55555555-5555-5555-5555-555555555555",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--55555555-1111-1111-1111-555555555555",
            "ipv4-addr--55555555-2222-2222-2222-555555555555"
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
        "id": "network-traffic--55555555-1111-1111-1111-555555555555",
        "dst_ref": "ipv4-addr--55555555-2222-2222-2222-555555555555",
        "dst_port": 5678,
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--55555555-2222-2222-2222-555555555555",
        "value": "5.6.7.8"
    },
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--66666666-6666-6666-6666-666666666666",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"btc-wallet\"",
            "misp:meta-category=\"financial\""
        ],
        "x_misp_attributes": [
            {
                "uuid": "66666666-1111-1111-1111-666666666666",
                "type": "btc",
                "object_relation": "wallet-address",
                "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
                "to_ids": True
            },
            {
                "uuid": "66666666-2222-2222-2222-666666666666",
                "type": "float",
                "object_relation": "balance_BTC",
                "value": "2.25036953"
            },
            {
                "uuid": "66666666-3333-3333-3333-666666666666",
                "type": "float",
                "object_relation": "BTC_received",
                "value": "3.35036953"
            },
            {
                "uuid": "66666666-4444-4444-4444-666666666666",
                "type": "float",
                "object_relation": "BTC_sent",
                "value": "1.1"
            }
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "btc-wallet"
    },
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--77777777-7777-7777-7777-777777777777",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--88888888-8888-8888-8888-888888888888",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
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
    },
    {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": "vulnerability--99999999-9999-9999-9999-999999999999",
        "created_by_ref": "identity--12345678-90ab-cdef-1234-567890abcdef",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "CVE-2021-29921",
        "description": "In Python before 3.9.5, the ipaddress library mishandles leading zero characters in the octets of an IP address string.",
        "labels": [
            "misp:name=\"vulnerability\"",
            "misp:meta-category=\"vulnerability\"",
            "misp:to_ids=\"False\""
        ],
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2021-29921"
            }
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--6b34f83c-f1db-4f39-a813-4ac86c1f2fe6",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "threatens",
        "source_ref": "attack-pattern--44444444-4444-4444-4444-444444444444",
        "target_ref": "indicator--88888888-8888-8888-8888-888888888888"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0ded93a1-38e5-4d2d-aecb-1f0e98daedb7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "related-to",
        "source_ref": "observed-data--55555555-5555-5555-5555-555555555555",
        "target_ref": "indicator--88888888-8888-8888-8888-888888888888"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--94057569-8790-4fd7-9a05-ed0a054a2390",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "connected-to",
        "source_ref": "x-misp-object--66666666-6666-6666-6666-666666666666",
        "target_ref": "indicator--88888888-8888-8888-8888-888888888888"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f5134684-d988-42bc-964e-f2a4686c42a0",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "protects-against",
        "source_ref": "course-of-action--77777777-7777-7777-7777-777777777777",
        "target_ref": "vulnerability--99999999-9999-9999-9999-999999999999"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--e239566f-cfb0-437d-a4b2-0695c9ceffe7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "protected-with",
        "source_ref": "indicator--88888888-8888-8888-8888-888888888888",
        "target_ref": "course-of-action--77777777-7777-7777-7777-777777777777"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--2cac5500-e293-4a61-a751-9d7ea9624692",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "affects",
        "source_ref": "vulnerability--99999999-9999-9999-9999-999999999999",
        "target_ref": "indicator--88888888-8888-8888-8888-888888888888"
    }
]
_BUNDLE_WITH_MULTIPLE_REPORTS = [
    {
        "name": "MISP-STIX-Converter test event with autonomous systems",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "Threat-Report",
            "misp:tool=\"MISP-STIX-Converter\""
        ],
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "id": "grouping--e2e6a6ea-f69b-4d93-8564-f51d67cafe51",
        "type": "grouping",
        "context": "suspicious-activity",
        "object_refs": [
            "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
            "autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f",
            "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
            "autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
            "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
            "relationship--a950cb91-1a8a-4c3a-ad73-3e2e38a39070"
        ],
        "spec_version": "2.1"
    },
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
    },
    {
        "id": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "type": "observed-data",
        "labels": [
            "misp:type=\"AS\"",
            "misp:category=\"Network activity\""
        ],
        "number_observed": 1,
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "object_refs": [
            "autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544"
        ],
        "spec_version": "2.1"
    },
    {
        "id": "autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "number": 66642,
        "type": "autonomous-system",
        "spec_version": "2.1"
    },
    {
        "name": "MISP-STIX-Converter test event with domains",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "Threat-Report",
            "misp:tool=\"MISP-STIX-Converter\""
        ],
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "id": "grouping--d402185f-c129-4f65-8678-43edb2cee1cf",
        "type": "grouping",
        "context": "suspicious-activity",
        "object_refs": [
            "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
            "indicator--4bb235a7-7d25-4aef-802f-2c6b45c5eceb",
            "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
            "relationship--0a2a52f1-cc81-4701-976a-d8d90a480f62"
        ],
        "spec_version": "2.1"
    },
    {
        "id": "indicator--4bb235a7-7d25-4aef-802f-2c6b45c5eceb",
        "type": "indicator",
        "labels": [
            "misp:type=\"domain\"",
            "misp:category=\"Network activity\"",
            "misp:to_ids=\"True\""
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Network activity"
            }
        ],
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "pattern": "[domain-name:value = 'circl.lu']",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "valid_from": "2020-10-25T16:22:00Z",
        "description": "Domain test attribute",
        "spec_version": "2.1",
        "pattern_type": "stix",
        "pattern_version": "2.1"
    },
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
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT - S0017",
        "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
        "aliases": [
            "BISCUIT"
        ],
        "labels": [
            "misp:galaxy-name=\"Malware\"",
            "misp:galaxy-type=\"mitre-malware\""
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--a950cb91-1a8a-4c3a-ad73-3e2e38a39070",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "describes",
        "source_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "target_ref": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0a2a52f1-cc81-4701-976a-d8d90a480f62",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "describes",
        "source_ref": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
        "target_ref": "indicator--4bb235a7-7d25-4aef-802f-2c6b45c5eceb"
    }
]
_BUNDLE_WITH_NO_REPORT = [
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
    },
    {
        "id": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "type": "observed-data",
        "labels": [
            "misp:type=\"AS\"",
            "misp:category=\"Network activity\""
        ],
        "number_observed": 1,
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "object_refs": [
            "autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544"
        ],
        "spec_version": "2.1"
    },
    {
        "id": "autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "number": 66642,
        "type": "autonomous-system",
        "spec_version": "2.1"
    },
    {
        "id": "indicator--4bb235a7-7d25-4aef-802f-2c6b45c5eceb",
        "type": "indicator",
        "labels": [
            "misp:type=\"domain\"",
            "misp:category=\"Network activity\"",
            "misp:to_ids=\"True\""
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Network activity"
            }
        ],
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "pattern": "[domain-name:value = 'circl.lu']",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "valid_from": "2020-10-25T16:22:00Z",
        "description": "Domain test attribute",
        "spec_version": "2.1",
        "pattern_type": "stix",
        "pattern_version": "2.1"
    },
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
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT - S0017",
        "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
        "aliases": [
            "BISCUIT"
        ],
        "labels": [
            "misp:galaxy-name=\"Malware\"",
            "misp:galaxy-type=\"mitre-malware\""
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--a950cb91-1a8a-4c3a-ad73-3e2e38a39070",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "describes",
        "source_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "target_ref": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0a2a52f1-cc81-4701-976a-d8d90a480f62",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "describes",
        "source_ref": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
        "target_ref": "indicator--4bb235a7-7d25-4aef-802f-2c6b45c5eceb"
    }
]
_BUNDLE_WITH_SIGHTINGS = [
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
            "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "sighting--5125aa81-ab95-4cdf-83f9-3c467207307d",
            "sighting--b5b53917-1556-4476-97eb-52e179e3393e",
            "opinion--ec85cc8c-205f-4b19-8f96-73ef80d24d13",
            "opinion--7ea813e5-6dd5-4241-83a7-37fb56da2d78",
            "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
            "sighting--5533d0db-b952-4609-b82d-59017f2454fc",
            "opinion--c7d12059-6a07-4423-a82a-f3bceaae33c8",
            "sighting--ec0c6809-9ccb-4201-bc47-d5ffc5ecaa88",
            "opinion--3ab7497e-39f5-4a0a-b797-dc08bf80631d"
        ],
        "labels": [
            "Threat-Report",
            "misp:tool=\"MISP-STIX-Converter\""
        ]
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"AS\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "number": 174
    },
    {
        "type": "sighting",
        "spec_version": "2.1",
        "id": "sighting--5125aa81-ab95-4cdf-83f9-3c467207307d",
        "created": "2020-10-25T16:22:05.000Z",
        "modified": "2020-10-25T16:22:05.000Z",
        "sighting_of_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "where_sighted_refs": [
            "identity--55f6ea5e-2c60-40e5-964f-47a8950d210f"
        ]
    },
    {
        "type": "sighting",
        "spec_version": "2.1",
        "id": "sighting--b5b53917-1556-4476-97eb-52e179e3393e",
        "created": "2020-10-25T16:22:30.000Z",
        "modified": "2020-10-25T16:22:30.000Z",
        "sighting_of_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "where_sighted_refs": [
            "identity--7b9774b7-528b-4b03-bbb8-a0dd9e546183"
        ]
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--ec85cc8c-205f-4b19-8f96-73ef80d24d13",
        "created": "2020-10-25T16:22:10.000Z",
        "modified": "2020-10-25T16:22:10.000Z",
        "explanation": "False positive Sighting",
        "authors": [
            "Oscorp Industries"
        ],
        "opinion": "strongly-disagree",
        "object_refs": [
            "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "x_misp_author_ref": "identity--93d5d857-822c-4c53-ae81-a05ffcbd2a90"
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--7ea813e5-6dd5-4241-83a7-37fb56da2d78",
        "created": "2020-10-25T16:22:20.000Z",
        "modified": "2020-10-25T16:22:20.000Z",
        "explanation": "False positive Sighting",
        "authors": [
            "Umbrella Corporation"
        ],
        "opinion": "strongly-disagree",
        "object_refs": [
            "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "x_misp_author_ref": "identity--91050751-c1c9-4944-a522-db6390cec15b"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Domain test attribute",
        "pattern": "[domain-name:value = 'circl.lu']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "sighting",
        "spec_version": "2.1",
        "id": "sighting--5533d0db-b952-4609-b82d-59017f2454fc",
        "created": "2020-10-25T16:22:05.000Z",
        "modified": "2020-10-25T16:22:05.000Z",
        "sighting_of_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "where_sighted_refs": [
            "identity--55f6ea5e-2c60-40e5-964f-47a8950d210f"
        ]
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--c7d12059-6a07-4423-a82a-f3bceaae33c8",
        "created": "2020-10-25T16:22:30.000Z",
        "modified": "2020-10-25T16:22:30.000Z",
        "explanation": "False positive Sighting",
        "authors": [
            "E-Corp"
        ],
        "opinion": "strongly-disagree",
        "object_refs": [
            "indicator--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "x_misp_author_ref": "identity--7b9774b7-528b-4b03-bbb8-a0dd9e546183"
    },
    {
        "type": "sighting",
        "spec_version": "2.1",
        "id": "sighting--ec0c6809-9ccb-4201-bc47-d5ffc5ecaa88",
        "created": "2020-10-25T16:22:20.000Z",
        "modified": "2020-10-25T16:22:20.000Z",
        "sighting_of_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "where_sighted_refs": [
            "identity--93d5d857-822c-4c53-ae81-a05ffcbd2a90"
        ]
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--3ab7497e-39f5-4a0a-b797-dc08bf80631d",
        "created": "2020-10-25T16:22:10.000Z",
        "modified": "2020-10-25T16:22:10.000Z",
        "explanation": "False positive Sighting",
        "authors": [
            "Umbrella Corporation"
        ],
        "opinion": "strongly-disagree",
        "object_refs": [
            "indicator--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "x_misp_author_ref": "identity--91050751-c1c9-4944-a522-db6390cec15b"
    },
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--55f6ea5e-2c60-40e5-964f-47a8950d210f",
        "created": "2022-07-11T14:11:39.134109Z",
        "modified": "2022-07-11T14:11:39.134109Z",
        "name": "CIRCL",
        "identity_class": "organization"
    },
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--7b9774b7-528b-4b03-bbb8-a0dd9e546183",
        "created": "2022-07-11T14:11:39.134416Z",
        "modified": "2022-07-11T14:11:39.134416Z",
        "name": "E-Corp",
        "identity_class": "organization"
    },
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--93d5d857-822c-4c53-ae81-a05ffcbd2a90",
        "created": "2022-07-11T14:11:39.134704Z",
        "modified": "2022-07-11T14:11:39.134704Z",
        "name": "Oscorp Industries",
        "identity_class": "organization"
    },
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--91050751-c1c9-4944-a522-db6390cec15b",
        "created": "2022-07-11T14:11:39.135147Z",
        "modified": "2022-07-11T14:11:39.135147Z",
        "name": "Umbrella Corporation",
        "identity_class": "organization"
    }
]
_CAMPAIGN_NAME_ATTRIBUTE = {
    "type": "campaign",
    "spec_version": "2.1",
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
_COURSE_OF_ACTION_GALAXY = {
    "type": "course-of-action",
    "spec_version": "2.1",
    "id": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Automated Exfiltration Mitigation - T1020",
    "description": "ATT&CK Mitigation | Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
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
_COURSE_OF_ACTION_OBJECT = {
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
_CPE_ASSET_INDICATOR_OBJECT = {
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
_CPE_ASSET_OBSERVABLE_OBJECT = [
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
_CREDENTIAL_INDICATOR_OBJECT = {
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
_CREDENTIAL_OBSERVABLE_OBJECT = [
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
_CUSTOM_ATTRIBUTES = [
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"btc\"",
            "misp:category=\"Financial fraud\"",
            "misp:to_ids=\"True\""
        ],
        "x_misp_category": "Financial fraud",
        "x_misp_comment": "Btc test attribute",
        "x_misp_type": "btc",
        "x_misp_value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE"
    },
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"iban\"",
            "misp:category=\"Financial fraud\"",
            "misp:to_ids=\"True\""
        ],
        "x_misp_category": "Financial fraud",
        "x_misp_comment": "IBAN test attribute",
        "x_misp_type": "iban",
        "x_misp_value": "LU1234567890ABCDEF1234567890"
    },
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--d94bdd2c-3603-4044-8b70-20090e7526ad",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"http-method\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_type": "http-method",
        "x_misp_value": "POST"
    },
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--1af096a0-efa1-4331-9300-a6b5eb4df2e6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"port\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_type": "port",
        "x_misp_value": "8443"
    },
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--8be8065b-ca71-4210-976e-2804665a502d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"size-in-bytes\"",
            "misp:category=\"Other\""
        ],
        "x_misp_category": "Other",
        "x_misp_type": "size-in-bytes",
        "x_misp_value": "1234"
    },
    {
        "type": "x-misp-attribute",
        "spec_version": "2.1",
        "id": "x-misp-attribute--f0b5b638-81b4-4509-bd40-1e114955caf4",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:type=\"user-agent\"",
            "misp:category=\"Network activity\""
        ],
        "x_misp_category": "Network activity",
        "x_misp_comment": "User-agent test attribute",
        "x_misp_type": "user-agent",
        "x_misp_value": "Mozilla Firefox"
    }
]
_CUSTOM_GALAXY = {
    "type": "x-misp-galaxy-cluster",
    "spec_version": "2.1",
    "id": "x-misp-galaxy-cluster--24430dc6-9c27-4b3c-a5e7-6dda478fffa0",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "labels": [
        "misp:galaxy-name=\"Tea Matrix\"",
        "misp:galaxy-type=\"tea-matrix\""
    ],
    "x_misp_description": "Tea Matrix | Milk in tea",
    "x_misp_name": "Tea Matrix",
    "x_misp_type": "tea-matrix",
    "x_misp_value": "Milk in tea"
}
_CUSTOM_OBJECTS = [
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--695e7924-2518-4054-9cea-f82853d37410",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"bank-account\"",
            "misp:meta-category=\"financial\""
        ],
        "x_misp_attributes": [
            {
                "type": "iban",
                "object_relation": "iban",
                "value": "LU1234567890ABCDEF1234567890",
                "to_ids": True,
                "uuid": "8acaad62-227a-4988-96e7-4586847421a2"
            },
            {
                "type": "bic",
                "object_relation": "swift",
                "value": "CTBKLUPP",
                "uuid": "c53382a1-cf4b-4901-a890-1611dbcc7101"
            },
            {
                "type": "bank-account-nr",
                "object_relation": "account",
                "value": "1234567890",
                "uuid": "c7c9f782-582f-4218-af79-e7901237e468"
            },
            {
                "type": "text",
                "object_relation": "institution-name",
                "value": "Central Bank",
                "uuid": "c206e7b4-7333-40a3-bf02-9647d32f9df2"
            },
            {
                "type": "text",
                "object_relation": "account-name",
                "value": "John Smith's bank account",
                "uuid": "f388d5e6-e4eb-401d-8ea4-efdd519659a1"
            },
            {
                "type": "text",
                "object_relation": "beneficiary",
                "value": "John Smith",
                "uuid": "c1ea07c0-a855-4c47-9df2-4acc0d3c4e63"
            },
            {
                "type": "text",
                "object_relation": "currency-code",
                "value": "EUR",
                "uuid": "5421d979-9af5-45ae-8c81-5005a4d7fc55"
            }
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "bank-account"
    },
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"btc-wallet\"",
            "misp:meta-category=\"financial\""
        ],
        "x_misp_attributes": [
            {
                "type": "btc",
                "object_relation": "wallet-address",
                "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
                "to_ids": True,
                "uuid": "b25b2538-36e3-4418-a42a-440eed163ffa"
            },
            {
                "type": "float",
                "object_relation": "balance_BTC",
                "value": "2.25036953",
                "uuid": "dd142f6f-d8a0-4143-92b3-3b50e7cb1c51"
            },
            {
                "type": "float",
                "object_relation": "BTC_received",
                "value": "3.35036953",
                "uuid": "7fd93652-5713-4390-bd15-94ec77e9c6d1"
            },
            {
                "type": "float",
                "object_relation": "BTC_sent",
                "value": "1.1",
                "uuid": "c5c0532c-2a63-4f40-86a7-df27914a177e"
            }
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "btc-wallet"
    },
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--868037d5-d804-4f1d-8016-f296361f9c68",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"person\"",
            "misp:meta-category=\"misc\""
        ],
        "x_misp_attributes": [
            {
                "type": "first-name",
                "object_relation": "first-name",
                "value": "John",
                "uuid": "37c42710-aaf7-4f10-956b-f8eb7adffb81"
            },
            {
                "type": "last-name",
                "object_relation": "last-name",
                "value": "Smith",
                "uuid": "05583483-4d7f-496a-aa1b-279d484b5966"
            },
            {
                "type": "nationality",
                "object_relation": "nationality",
                "value": "USA",
                "uuid": "a4e174fc-f341-432f-beb3-27b99ec22541"
            },
            {
                "type": "passport-number",
                "object_relation": "passport-number",
                "value": "ABA9875413",
                "uuid": "f6f12b78-5f96-4c64-9462-2e881d70cd4a"
            },
            {
                "type": "phone-number",
                "object_relation": "phone-number",
                "value": "0123456789",
                "uuid": "6c0a87f4-54a3-401a-a37f-13b2996d4d37"
            }
        ],
        "x_misp_meta_category": "misc",
        "x_misp_name": "person"
    },
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--3e76898a-fcb1-485b-ac24-d450fe8c54bc",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"report\"",
            "misp:meta-category=\"misc\""
        ],
        "x_misp_attributes": [
            {
                "type": "text",
                "object_relation": "summary",
                "value": "It is compromised",
                "uuid": "11798cf8-1f53-448d-b424-e0bd7402492c"
            },
            {
                "type": "text",
                "object_relation": "type",
                "value": "Report",
                "uuid": "84a5575e-bbe4-4a55-a75d-c4a91b0d1e23"
            },
            {
                "type": "attachment",
                "value": "report.md",
                "object_relation": "report-file",
                "data": "VGhyZWF0IFJlcG9ydAoKSXQgaXMgY29tcHJvbWlzZWQK",
                "uuid": "5742717c-7689-4440-af20-3cb44edb45cf"
            }
        ],
        "x_misp_meta_category": "misc",
        "x_misp_name": "report"
    }
]
_DOMAIN_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Domain test attribute",
    "pattern": "[domain-name:value = 'circl.lu']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_DOMAIN_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"domain\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
    }
]
_DOMAIN_IP_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Domain|ip test attribute",
    "pattern": "[domain-name:value = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_DOMAIN_IP_INDICATOR_OBJECT = {
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
_DOMAIN_IP_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"domain|ip\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu",
        "resolves_to_refs": [
            "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "149.13.33.14"
    }
]
_DOMAIN_IP_OBSERVABLE_OBJECTS = [
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
    },
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
_EMAIL_ATTACHMENT_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Email attachment test attribute",
    "pattern": "[email-message:body_multipart[*].body_raw_ref.name = 'email_attachment.test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_ATTACHMENT_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"email-attachment\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_multipart": True,
        "body_multipart": [
            {
                "body_raw_ref": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "content_disposition": "attachment; filename='email_attachment.test'"
            }
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "email_attachment.test"
    }
]
_EMAIL_BODY_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:body = 'Email body test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_BODY_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"email-body\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_multipart": False,
        "body": "Email body test"
    }
]
_EMAIL_DESTINATION_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Destination email address test attribute",
    "pattern": "[email-message:to_refs[*].value = 'dst@email.test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_DESTINATION_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--518b4bcb-a86b-4783-9457-391d548b605b",
            "email-addr--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"email-dst\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--518b4bcb-a86b-4783-9457-391d548b605b",
        "is_multipart": False,
        "to_refs": [
            "email-addr--518b4bcb-a86b-4783-9457-391d548b605b"
        ]
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "dst@email.test"
    }
]
_EMAIL_HEADER_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:received_lines = 'from mail.example.com ([198.51.100.3]) by smtp.gmail.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_HEADER_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"email-header\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_multipart": False,
        "received_lines": [
            "from mail.example.com ([198.51.100.3]) by smtp.gmail.com"
        ]
    }
]
_EMAIL_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-addr:value = 'address@email.test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_INDICATOR_OBJECT = {
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
_EMAIL_MESSAGE_ID_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--f3745b11-2b82-4798-80ba-d32c506135ec",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:message_id = '1234']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2020-10-25T16:22:00Z",
    "kill_chain_phases": [
        {
            "kill_chain_name": "misp-category",
            "phase_name": "Payload delivery"
        }
    ],
    "labels": [
        "misp:type=\"email-message-id\"",
        "misp:category=\"Payload delivery\"",
        "misp:to_ids=\"True\""
    ]
}
_EMAIL_MESSAGE_ID_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f3745b11-2b82-4798-80ba-d32c506135ec",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--f3745b11-2b82-4798-80ba-d32c506135ec"
        ],
        "labels": [
            "misp:type=\"email-message-id\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--f3745b11-2b82-4798-80ba-d32c506135ec",
        "is_multipart": False,
        "message_id": "1234"
    }
]
_EMAIL_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"email\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "address@email.test"
    }
]
_EMAIL_OBSERVABLE_OBJECT = [
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
        "is_multipart": True,
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
_EMAIL_REPLY_TO_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:additional_header_fields.reply_to = 'reply-to@email.test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_REPLY_TO_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
        ],
        "labels": [
            "misp:type=\"email-reply-to\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "is_multipart": False,
        "additional_header_fields": {
            "Reply-To": "reply-to@email.test"
        }
    }
]
_EMAIL_SOURCE_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Source email address test attribute",
    "pattern": "[email-message:from_ref.value = 'src@email.test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_SOURCE_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"email-src\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_multipart": False,
        "from_ref": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "src@email.test"
    }
]
_EMAIL_SUBJECT_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:subject = 'Test Subject']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_SUBJECT_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ],
        "labels": [
            "misp:type=\"email-subject\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "is_multipart": False,
        "subject": "Test Subject"
    }
]
_EMAIL_X_MAILER_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--f09d8496-e2ba-4250-878a-bec9b85c7e96",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:additional_header_fields.x_mailer = 'Email X-Mailer test']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_EMAIL_X_MAILER_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f09d8496-e2ba-4250-878a-bec9b85c7e96",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "email-message--f09d8496-e2ba-4250-878a-bec9b85c7e96"
        ],
        "labels": [
            "misp:type=\"email-x-mailer\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--f09d8496-e2ba-4250-878a-bec9b85c7e96",
        "is_multipart": False,
        "additional_header_fields": {
            "X-Mailer": "Email X-Mailer test"
        }
    }
]
_EMPLOYEE_OBJECT = {
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
_FILE_AND_PE_INDICATOR_OBJECT = {
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
_FILE_AND_PE_OBSERVABLE_OBJECT = [
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
_FILE_INDICATOR_OBJECT = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
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
_FILE_OBSERVABLE_OBJECT = [
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
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802"
        },
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected",
        "x_misp_filename": "oui"
    }
]
_FILENAME_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Filename test attribute",
    "pattern": "[file:name = 'test_file_name']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_FILENAME_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"filename\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "test_file_name"
    }
]
_GEOLOCATION_OBJECT = {
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
_GITHUB_USERNAME_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Github username test attribute",
    "pattern": "[user-account:account_type = 'github' AND user-account:account_login = 'chrisr3d']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_GITHUB_USERNAME_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"github-username\"",
            "misp:category=\"Social network\""
        ]
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "account_login": "chrisr3d",
        "account_type": "github"
    }
]
_HASH_COMPOSITE_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|md5 test attribute",
        "pattern": "[file:name = 'filename1' AND file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha1 test attribute",
        "pattern": "[file:name = 'filename2' AND file:hashes.SHA1 = '2920d5e6c579fce772e5506caf03af65579088bd']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha224 test attribute",
        "pattern": "[file:name = 'filename3' AND file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha256 test attribute",
        "pattern": "[file:name = 'filename4' AND file:hashes.SHA256 = '7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha384 test attribute",
        "pattern": "[file:name = 'filename5' AND file:hashes.SHA384 = 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512 test attribute",
        "pattern": "[file:name = 'filename6' AND file:hashes.SHA512 = '28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|ssdeep test attribute",
        "pattern": "[file:name = 'filename7' AND file:hashes.SSDEEP = '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|authentihash test attribute",
        "pattern": "[file:name = 'filename8' AND file:hashes.AUTHENTIHASH = 'b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"filename|authentihash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|imphash test attribute",
        "pattern": "[file:name = 'filename9' AND file:hashes.IMPHASH = '68f013d7437aa653a8a98a05807afeb1']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"filename|imphash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|pehash test attribute",
        "pattern": "[file:name = 'filename10' AND file:hashes.PEHASH = 'ffb7a38174aab4744cc4a509e34800aee9be8e57']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"filename|pehash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512/256 test attribute",
        "pattern": "[file:name = 'filename11' AND file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|tlsh test attribute",
        "pattern": "[file:name = 'filename12' AND file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|vhash test attribute",
        "pattern": "[file:name = 'filename13' AND file:hashes.VHASH = '115056655d15151138z66hz1021z55z66z3']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"filename|vhash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-256 test attribute",
        "pattern": "[file:name = 'filename14' AND file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_HASH_COMPOSITE_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ],
        "labels": [
            "misp:type=\"filename|md5\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {
            "MD5": "b2a5abfeef9e36964281a31e17b57c97"
        },
        "name": "filename1"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
        ],
        "labels": [
            "misp:type=\"filename|sha1\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "hashes": {
            "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
        },
        "name": "filename2"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--90bd7dae-b78c-4025-9073-568950c780fb"
        ],
        "labels": [
            "misp:type=\"filename|sha224\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--90bd7dae-b78c-4025-9073-568950c780fb",
        "hashes": {
            "SHA224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
        },
        "name": "filename3"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--2007ec09-8137-4a71-a3ce-6ef967bebacf"
        ],
        "labels": [
            "misp:type=\"filename|sha256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "hashes": {
            "SHA-256": "7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4"
        },
        "name": "filename4"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--c8760340-85a9-4e40-bfde-522d66ef1e9f"
        ],
        "labels": [
            "misp:type=\"filename|sha384\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "hashes": {
            "SHA384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
        },
        "name": "filename5"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--55ffda25-c3fe-48b5-a6eb-59c986cb593e"
        ],
        "labels": [
            "misp:type=\"filename|sha512\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "hashes": {
            "SHA-512": "28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe"
        },
        "name": "filename6"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--9060e814-a36f-45ab-84e5-66fc82dc7cff"
        ],
        "labels": [
            "misp:type=\"filename|ssdeep\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "hashes": {
            "SSDEEP": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
        },
        "name": "filename7"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"filename|authentihash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {
            "AUTHENTIHASH": "b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc"
        },
        "name": "filename8"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"filename|imphash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {
            "IMPHASH": "68f013d7437aa653a8a98a05807afeb1"
        },
        "name": "filename9"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
        ],
        "labels": [
            "misp:type=\"filename|pehash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "hashes": {
            "PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"
        },
        "name": "filename10"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a"
        ],
        "labels": [
            "misp:type=\"filename|sha512/256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "hashes": {
            "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
        },
        "name": "filename11"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--7467406e-88d3-4856-afc9-412459bc3c8b"
        ],
        "labels": [
            "misp:type=\"filename|tlsh\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7467406e-88d3-4856-afc9-412459bc3c8b",
        "hashes": {
            "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
        },
        "name": "filename12"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975"
        ],
        "labels": [
            "misp:type=\"filename|vhash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "hashes": {
            "VHASH": "115056655d15151138z66hz1021z55z66z3"
        },
        "name": "filename13"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6"
        ],
        "labels": [
            "misp:type=\"filename|sha3-256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "hashes": {
            "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
        },
        "name": "filename14"
    }
]
_HASH_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "MD5 test attribute",
        "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA1 test attribute",
        "pattern": "[file:hashes.SHA1 = '2920d5e6c579fce772e5506caf03af65579088bd']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA224 test attribute",
        "pattern": "[file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA256 test attribute",
        "pattern": "[file:hashes.SHA256 = '7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA384 test attribute",
        "pattern": "[file:hashes.SHA384 = 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA512 test attribute",
        "pattern": "[file:hashes.SHA512 = '28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SSDEEP test attribute",
        "pattern": "[file:hashes.SSDEEP = '96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "AUTHENTIHASH test attribute",
        "pattern": "[file:hashes.AUTHENTIHASH = 'b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"authentihash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "IMPHASH test attribute",
        "pattern": "[file:hashes.IMPHASH = '68f013d7437aa653a8a98a05807afeb1']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"imphash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "PEHASH test attribute",
        "pattern": "[file:hashes.PEHASH = 'ffb7a38174aab4744cc4a509e34800aee9be8e57']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"pehash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA512/256 test attribute",
        "pattern": "[file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "TLSH test attribute",
        "pattern": "[file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "VHASH test attribute",
        "pattern": "[file:hashes.VHASH = '115056655d15151138z66hz1021z55z66z3']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"vhash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA3-256 test attribute",
        "pattern": "[file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--4846cade-2492-4e7d-856e-2afcd282455b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "TELFHASH test attribute",
        "pattern": "[file:hashes.TELFHASH = 'b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload delivery"
            }
        ],
        "labels": [
            "misp:type=\"telfhash\"",
            "misp:category=\"Payload delivery\"",
            "misp:to_ids=\"True\""
        ]
    }
]
_HASH_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ],
        "labels": [
            "misp:type=\"md5\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {
            "MD5": "b2a5abfeef9e36964281a31e17b57c97"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
        ],
        "labels": [
            "misp:type=\"sha1\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "hashes": {
            "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--90bd7dae-b78c-4025-9073-568950c780fb"
        ],
        "labels": [
            "misp:type=\"sha224\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--90bd7dae-b78c-4025-9073-568950c780fb",
        "hashes": {
            "SHA224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--2007ec09-8137-4a71-a3ce-6ef967bebacf"
        ],
        "labels": [
            "misp:type=\"sha256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "hashes": {
            "SHA-256": "7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--c8760340-85a9-4e40-bfde-522d66ef1e9f"
        ],
        "labels": [
            "misp:type=\"sha384\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "hashes": {
            "SHA384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--55ffda25-c3fe-48b5-a6eb-59c986cb593e"
        ],
        "labels": [
            "misp:type=\"sha512\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "hashes": {
            "SHA-512": "28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--9060e814-a36f-45ab-84e5-66fc82dc7cff"
        ],
        "labels": [
            "misp:type=\"ssdeep\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "hashes": {
            "SSDEEP": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"authentihash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {
            "AUTHENTIHASH": "b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"imphash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {
            "IMPHASH": "68f013d7437aa653a8a98a05807afeb1"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
        ],
        "labels": [
            "misp:type=\"pehash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "hashes": {
            "PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a"
        ],
        "labels": [
            "misp:type=\"sha512/256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "hashes": {
            "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--7467406e-88d3-4856-afc9-412459bc3c8b"
        ],
        "labels": [
            "misp:type=\"tlsh\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7467406e-88d3-4856-afc9-412459bc3c8b",
        "hashes": {
            "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975"
        ],
        "labels": [
            "misp:type=\"vhash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "hashes": {
            "VHASH": "115056655d15151138z66hz1021z55z66z3"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6"
        ],
        "labels": [
            "misp:type=\"sha3-256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "hashes": {
            "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--4846cade-2492-4e7d-856e-2afcd282455b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--4846cade-2492-4e7d-856e-2afcd282455b"
        ],
        "labels": [
            "misp:type=\"telfhash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--4846cade-2492-4e7d-856e-2afcd282455b",
        "hashes": {
            "TELFHASH": "b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b"
        }
    }
]
_HOSTNAME_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Hostname test attribute",
    "pattern": "[domain-name:value = 'circl.lu']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_HOSTNAME_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"hostname\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
    }
]
_HOSTNAME_PORT_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Hostname|port test attribute",
    "pattern": "[domain-name:value = 'circl.lu' AND network-traffic:dst_port = '8443']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_HOSTNAME_PORT_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"hostname|port\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "dst_ref": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "dst_port": 8443,
        "protocols": [
            "tcp"
        ]
    }
]
_HTTP_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:extensions.'http-request-ext'.request_method = 'POST']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "User-agent test attribute",
        "pattern": "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'Mozilla Firefox']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_HTTP_REQUEST_INDICATOR_OBJECT = {
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
_HTTP_REQUEST_OBSERVABLE_OBJECT = [
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
_IMAGE_INDICATOR_OBJECT = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--939b2f03-c487-4f62-a90e-cab7acfee294",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
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
_IMAGE_OBSERVABLE_OBJECT = [
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
        "x_misp_filename": "STIX.png",
        "x_misp_url": "https://oasis-open.github.io/cti-documentation/img/STIX.png"
    }
]
_INTRUSION_SET_GALAXY = {
    "type": "intrusion-set",
    "spec_version": "2.1",
    "id": "intrusion-set--d6e88e18-81e8-4709-82d8-973095da1e70",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "APT16 - G0023",
    "description": "Name of ATT&CK Group | APT16 is a China-based threat group that has launched spearphishing campaigns targeting Japanese and Taiwanese organizations.",
    "aliases": [
        "APT16"
    ],
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
_IP_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Source IP test attribute",
        "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Destination IP test attribute",
        "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_IP_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"ip-src\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "1.2.3.4"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
            "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"ip-dst\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "5.6.7.8"
    }
]
_IP_PORT_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Source IP | Port test attribute",
        "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4' AND network-traffic:src_port = '1234']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Destination IP | Port test attribute",
        "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8' AND network-traffic:dst_port = '5678']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_IP_PORT_INDICATOR_OBJECT = {
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
_IP_PORT_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"ip-src|port\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_port": 1234,
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "1.2.3.4"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
            "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"ip-dst|port\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_port": 5678,
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "5.6.7.8"
    }
]
_IP_PORT_OBSERVABLE_OBJECT = [
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
_LEGAL_ENTITY_OBJECT = {
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
    "x_misp_registration_number": "11223344556677889900",
    "x_misp_logo": {
        "value": "umbrella_logo"
    }
}
_LNK_INDICATOR_OBJECT = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
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
_LNK_OBSERVABLE_OBJECT = [
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
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802"
        },
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected",
        "x_misp_filename": "oui"
    }
]
_LOCATION_GALAXIES = [
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--84668357-5a8c-4bdd-9f0f-6b50b2535745",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "sweden",
        "description": "Country meta information | Sweden",
        "country": "SE",
        "labels": [
            "misp:galaxy-name=\"Country\"",
            "misp:galaxy-type=\"country\""
        ],
        "x_misp_Capital": "Stockholm",
        "x_misp_Continent": "EU",
        "x_misp_CurrencyCode": "SEK",
        "x_misp_CurrencyName": "Krona",
        "x_misp_ISO": "SE",
        "x_misp_ISO3": "SWE",
        "x_misp_Languages": "sv-SE,se,sma,fi-SE",
        "x_misp_Population": "9828655",
        "x_misp_tld": ".se"
    },
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--f93cb275-0366-4ecc-abf0-a17928d1e177",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Northern Europe",
        "description": "Regions based on UN M49 | Nothern Europe",
        "region": "northern-europe",
        "labels": [
            "misp:galaxy-name=\"Regions UN M49\"",
            "misp:galaxy-type=\"region\""
        ],
        "x_misp_subregion": [
            "830 - Channel Islands",
            "248 - \u00c5land Islands",
            "208 - Denmark",
            "233 - Estonia",
            "234 - Faroe Islands",
            "246 - Finland",
            "352 - Iceland",
            "372 - Ireland",
            "833 - Isle of Man",
            "428 - Latvia",
            "440 - Lithuania",
            "578 - Norway",
            "744 - Svalbard and Jan Mayen Islands",
            "752 - Sweden",
            "826 - United Kingdom of Great Britain and Northern Ireland"
        ]
    }
]
_MAC_ADDRESS_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[mac-addr:value = '12:34:56:78:90:AB']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_MAC_ADDRESS_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"mac-address\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": "mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "12:34:56:78:90:ab"
    }
]
_MALWARE_GALAXY = {
    "type": "malware",
    "spec_version": "2.1",
    "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "BISCUIT - S0017",
    "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
    "is_family": False,
    "aliases": [
        "BISCUIT"
    ],
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
            "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report-appendix.zip"
        }
    ],
    "x_misp_mitre_platforms": [
        "Windows"
    ]
}
_MALWARE_SAMPLE_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Malware Sample test attribute",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_MALWARE_SAMPLE_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"malware-sample\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802"
        },
        "name": "oui",
        "content_ref": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "mime_type": "application/zip",
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected"
    }
]
_MUTEX_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Mutex test attribute",
    "pattern": "[mutex:name = 'MutexTest']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_MUTEX_INDICATOR_OBJECT = {
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
_MUTEX_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"mutex\"",
            "misp:category=\"Artifacts dropped\""
        ]
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "MutexTest"
    }
]
_MUTEX_OBSERVABLE_OBJECT = [
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
_NETFLOW_INDICATOR_OBJECT = {
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
_NETFLOW_OBSERVABLE_OBJECT = [
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
_NETWORK_CONNECTION_INDICATOR_OBJECT = {
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
_NETWORK_CONNECTION_OBSERVABLE_OBJECT = [
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
_NETWORK_SOCKET_INDICATOR_OBJECT = {
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
_NETWORK_SOCKET_OBSERVABLE_OBJECT = [
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
                "is_listening": True,
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
_NEWS_AGENCY_OBJECT = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--d17e31ce-5a7a-4713-bdff-49d89548c259",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Agence France-Presse",
    "identity_class": "organization",
    "contact_information": "address: 13 place de la Bourse, 75002 Paris; Southern Railway Building, 1500 K Street, NW, Suite 600 / e-mail: contact@afp.fr; contact@afp.us / phone-number: (33)0140414646; (1)2024140600",
    "labels": [
        "misp:name=\"news-agency\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
    ],
    "x_misp_attachment": {
        "value": "AFP_logo.png",
    },
    "x_misp_link": "https://www.afp.com/"
}
_OBJECTS_WITH_REFERENCES = [
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7205da54-70de-4fa7-9b34-e14e63fe6787",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Buffer Overflow in Local Command-Line Utilities",
        "description": "This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root.",
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
    },
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
    },
    {
        "type": "x-misp-object",
        "spec_version": "2.1",
        "id": "x-misp-object--6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "labels": [
            "misp:name=\"btc-wallet\"",
            "misp:meta-category=\"financial\""
        ],
        "x_misp_attributes": [
            {
                "type": "btc",
                "object_relation": "wallet-address",
                "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
                "to_ids": True
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
        ],
        "x_misp_meta_category": "financial",
        "x_misp_name": "btc-wallet"
    },
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
    },
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
    },
    {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": "vulnerability--651a981f-6f59-4609-b735-e57efb9d44df",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "CVE-2021-29921",
        "description": "In Python before 3.9.5, the ipaddress library mishandles leading zero characters in the octets of an IP address string.",
        "labels": [
            "misp:name=\"vulnerability\"",
            "misp:meta-category=\"vulnerability\"",
            "misp:to_ids=\"False\""
        ],
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2021-29921"
            }
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--6b34f83c-f1db-4f39-a813-4ac86c1f2fe6",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "threatens",
        "source_ref": "attack-pattern--7205da54-70de-4fa7-9b34-e14e63fe6787",
        "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0ded93a1-38e5-4d2d-aecb-1f0e98daedb7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "includes",
        "source_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--94057569-8790-4fd7-9a05-ed0a054a2390",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "connected-to",
        "source_ref": "x-misp-object--6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
        "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f5134684-d988-42bc-964e-f2a4686c42a0",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "protects-against",
        "source_ref": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
        "target_ref": "vulnerability--651a981f-6f59-4609-b735-e57efb9d44df"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--e239566f-cfb0-437d-a4b2-0695c9ceffe7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "protected-with",
        "source_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
        "target_ref": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a"
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--2cac5500-e293-4a61-a751-9d7ea9624692",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "affects",
        "source_ref": "vulnerability--651a981f-6f59-4609-b735-e57efb9d44df",
        "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
    }
]
_ORGANIZATION_OBJECT = {
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
_PATTERNING_LANGUAGE_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Sigma test attribute",
        "pattern": "[title: Ps.exe Renamed SysInternals Tool description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documentied in TA17-293A report reference: https://www.us-cert.gov/ncas/alerts/TA17-293A author: Florian Roth date: 2017/10/22 logsource: product: windows service: sysmon detection: selection: EventID: 1 CommandLine: 'ps.exe -accepteula' condition: selection falsepositives: - Renamed SysInternals tool level: high]",
        "pattern_type": "sigma",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Artifacts dropped"
            }
        ],
        "labels": [
            "misp:type=\"sigma\"",
            "misp:category=\"Artifacts dropped\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Snort test attribute",
        "pattern": "[alert http any 443 -> 8.8.8.8 any]",
        "pattern_type": "snort",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Network activity"
            }
        ],
        "labels": [
            "misp:type=\"snort\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Yara test attribute",
        "pattern": "[rule torcryptomining { meta: description = \"Tor miner - broken UPX magic string\" strings: $upx_erase = {(00 FF 99 41|DF DD 30 33)} condition: $upx_erase at 236 }]",
        "pattern_type": "yara",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "Payload installation"
            }
        ],
        "labels": [
            "misp:type=\"yara\"",
            "misp:category=\"Payload installation\""
        ]
    }
]
_PATTERNING_LANGUAGE_OBJECTS = [
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
    },
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
    },
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
]
_PORT_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[network-traffic:dst_port = '8443']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_PROCESS_INDICATOR_OBJECT = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--5e39776a-b284-40b3-8079-22fea964451a",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[process:pid = '2510' AND process:image_ref.name = 'test_process.exe' AND process:parent_ref.command_line = 'grep -nrG iglocska /home/viktor/friends.txt' AND process:parent_ref.image_ref.name = 'parent_process.exe' AND process:parent_ref.pid = '2107' AND process:parent_ref.x_misp_process_name = 'Friends_From_H' AND process:child_refs[0].pid = '1401' AND process:is_hidden = 'True' AND process:x_misp_name = 'TestProcess' AND process:x_misp_port = '1234']",
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
_PROCESS_OBSERVABLE_OBJECT = [
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
        "pid": 2510,
        "image_ref": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "parent_ref": "process--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "child_refs": [
            "process--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "is_hidden": True,
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
_REGISTRY_KEY_INDICATOR_OBJECT = {
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
_REGISTRY_KEY_OBSERVABLE_OBJECT = [
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
_REGKEY_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Regkey test attribute",
    "pattern": "[windows-registry-key:key = 'HKLM\\\\Software\\\\mthjk']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_REGKEY_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"regkey\"",
            "misp:category=\"Persistence mechanism\""
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "key": "HKLM\\Software\\mthjk"
    }
]
_REGKEY_VALUE_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Regkey | value test attribute",
    "pattern": "[windows-registry-key:key = 'HKLM\\\\Software\\\\mthjk' AND windows-registry-key:values.data = '\\\\%DATA\\\\%\\\\1234567890']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_REGKEY_VALUE_OBSERVABLE_ATTRIBUTE = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"regkey|value\"",
            "misp:category=\"Persistence mechanism\""
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "key": "HKLM\\Software\\mthjk",
        "values": [
            {
                "data": "%DATA%\\1234567890"
            }
        ]
    }
]
_SCRIPT_OBJECTS = [
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--ce12c406-cf09-457b-875a-41ab75d6dc4d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "infected.py",
        "description": "A script that infects command line shells",
        "is_family": False,
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
    },
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
]
_SECTOR_GALAXY = {
    "type": "identity",
    "spec_version": "2.1",
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
_SIZE_IN_BYTES_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[file:size = '1234']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
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
_THREAT_ACTOR_GALAXY = {
    "type": "threat-actor",
    "spec_version": "2.1",
    "id": "threat-actor--11e17436-6ede-4733-8547-4ce0254ea19e",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Cutting Kitten",
    "description": "Threat actors are characteristics of malicious actors. | These convincing profiles form a self-referenced network of seemingly established LinkedIn users.",
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
_TOOL_GALAXY = {
    "type": "tool",
    "spec_version": "2.1",
    "id": "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "cmd - S0106",
    "description": "Name of ATT&CK software | cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
    "aliases": [
        "cmd",
        "cmd.exe"
    ],
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
    ]
}
_URL_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Link test attribute",
        "pattern": "[url:value = 'https://misp-project.org/download/']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "misp-category",
                "phase_name": "External analysis"
            }
        ],
        "labels": [
            "misp:type=\"link\"",
            "misp:category=\"External analysis\"",
            "misp:to_ids=\"True\""
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "URI test attribute",
        "pattern": "[url:value = 'https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "URL test attribute",
        "pattern": "[url:value = 'https://vm.misp-project.org/latest/']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_URL_INDICATOR_OBJECT = {
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
_URL_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"link\"",
            "misp:category=\"External analysis\""
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "https://misp-project.org/download/"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "url--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"uri\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "url--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ],
        "labels": [
            "misp:type=\"url\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "value": "https://vm.misp-project.org/latest/"
    }
]
_URL_OBSERVABLE_OBJECT = [
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
_VULNERABILITY_ATTRIBUTE = {
    "type": "vulnerability",
    "spec_version": "2.1",
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
_VULNERABILITY_GALAXY = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--a1640081-aa8d-4070-84b2-d23e2ae82799",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Ghost",
    "description": "List of known vulnerabilities and exploits | The GHOST vulnerability is a serious weakness in the Linux glibc library.",
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
_VULNERABILITY_OBJECT = {
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
_X509_FINGERPRINT_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "X509 MD5 fingerprint test attribute",
        "pattern": "[x509-certificate:hashes.MD5 = '8764605c6f388c89096b534d33565802']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "X509 SHA1 fingerprint test attribute",
        "pattern": "[x509-certificate:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "X509 SHA256 fingerprint test attribute",
        "pattern": "[x509-certificate:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
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
]
_X509_FINGERPRINT_OBSERVABLE_ATTRIBUTES = [
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
        ],
        "labels": [
            "misp:type=\"x509-fingerprint-md5\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {
            "MD5": "8764605c6f388c89096b534d33565802"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "x509-certificate--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "labels": [
            "misp:type=\"x509-fingerprint-sha1\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {
            "SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86"
        }
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "x509-certificate--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
        ],
        "labels": [
            "misp:type=\"x509-fingerprint-sha256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {
            "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
        }
    }
]
_X509_INDICATOR_OBJECT = {
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
_X509_OBSERVABLE_OBJECT = [
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


class TestInternalSTIX21Bundles:
    __bundle = {
        "type": "bundle",
        "id": "bundle--1dec4c6d-b06a-4f9a-a3e9-7bcdbac4f83a"
    }
    __identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-Project",
        "identity_class": "organization"
    }
    __grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "MISP-STIX-Converter test event",
        "context": "suspicious-activity",
        "labels": [
            "Threat-Report",
            "misp:tool=\"MISP-STIX-Converter\""
        ]
    }

    @classmethod
    def __assemble_bundle(cls, *stix_objects):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            deepcopy(cls.__identity),
            deepcopy(cls.__grouping),
            *stix_objects
        ]
        bundle['objects'][1]['object_refs'] = [stix_object['id'] for stix_object in stix_objects]
        return dict_to_stix2(bundle, allow_custom=True)

    ################################################################################
    #                              ATTRIBUTES SAMPLES                              #
    ################################################################################

    @classmethod
    def get_bundle_with_AS_indicator_attribute(cls):
        return cls.__assemble_bundle(_AS_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_AS_observable_attribute(cls):
        return cls.__assemble_bundle(*_AS_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_attachment_indicator_attribute(cls):
        return cls.__assemble_bundle(_ATTACHMENT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_attachment_observable_attribute(cls):
        return cls.__assemble_bundle(*_ATTACHMENT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_campaign_name_attribute(cls):
        return cls.__assemble_bundle(_CAMPAIGN_NAME_ATTRIBUTE)

    @classmethod
    def get_bundle_with_custom_attributes(cls):
        return cls.__assemble_bundle(*_CUSTOM_ATTRIBUTES)

    @classmethod
    def get_bundle_with_domain_indicator_attribute(cls):
        return cls.__assemble_bundle(_DOMAIN_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_domain_ip_indicator_attribute(cls):
        return cls.__assemble_bundle(_DOMAIN_IP_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_domain_ip_observable_attribute(cls):
        return cls.__assemble_bundle(*_DOMAIN_IP_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_domain_observable_attribute(cls):
        return cls.__assemble_bundle(*_DOMAIN_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_attachment_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_ATTACHMENT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_attachment_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_ATTACHMENT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_body_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_BODY_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_body_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_BODY_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_destination_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_DESTINATION_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_destination_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_DESTINATION_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_header_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_HEADER_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_header_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_HEADER_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_message_id_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_MESSAGE_ID_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_message_id_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_MESSAGE_ID_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_reply_to_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_REPLY_TO_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_reply_to_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_REPLY_TO_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_source_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SOURCE_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_source_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_SOURCE_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_subject_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SUBJECT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_subject_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_SUBJECT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_x_mailer_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_X_MAILER_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_x_mailer_observable_attribute(cls):
        return cls.__assemble_bundle(*_EMAIL_X_MAILER_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_filename_indicator_attribute(cls):
        return cls.__assemble_bundle(_FILENAME_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_filename_observable_attribute(cls):
        return cls.__assemble_bundle(*_FILENAME_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_galaxy_embedded_in_attribute(cls):
        return cls.__assemble_bundle(*_ATTRIBUTE_WITH_EMBEDDED_GALAXY)

    @classmethod
    def get_bundle_with_github_username_indicator_attribute(cls):
        return cls.__assemble_bundle(_GITHUB_USERNAME_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_github_username_observable_attribute(cls):
        return cls.__assemble_bundle(*_GITHUB_USERNAME_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hash_composite_indicator_attributes(cls):
        return cls.__assemble_bundle(*_HASH_COMPOSITE_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_hash_composite_observable_attributes(cls):
        return cls.__assemble_bundle(*_HASH_COMPOSITE_OBSERVABLE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_hash_indicator_attributes(cls):
        return cls.__assemble_bundle(*_HASH_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_hash_observable_attributes(cls):
        return cls.__assemble_bundle(*_HASH_OBSERVABLE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_hostname_indicator_attribute(cls):
        return cls.__assemble_bundle(_HOSTNAME_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hostname_observable_attribute(cls):
        return cls.__assemble_bundle(*_HOSTNAME_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hostname_port_indicator_attribute(cls):
        return cls.__assemble_bundle(_HOSTNAME_PORT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hostname_port_observable_attribute(cls):
        return cls.__assemble_bundle(*_HOSTNAME_PORT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_http_indicator_attributes(cls):
        return cls.__assemble_bundle(*_HTTP_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_ip_indicator_attributes(cls):
        return cls.__assemble_bundle(*_IP_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_ip_observable_attributes(cls):
        return cls.__assemble_bundle(*_IP_OBSERVABLE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_ip_port_indicator_attributes(cls):
        return cls.__assemble_bundle(*_IP_PORT_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_ip_port_observable_attributes(cls):
        return cls.__assemble_bundle(*_IP_PORT_OBSERVABLE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_mac_address_indicator_attribute(cls):
        return cls.__assemble_bundle(_MAC_ADDRESS_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_mac_address_observable_attribute(cls):
        return cls.__assemble_bundle(*_MAC_ADDRESS_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_malware_sample_indicator_attribute(cls):
        indicator = deepcopy(_MALWARE_SAMPLE_INDICATOR_ATTRIBUTE)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            pattern = [
                "file:name = 'oui'",
                "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                f"file:content_ref.payload_bin = '{b64encode(f.read()).decode()}'",
                "file:content_ref.mime_type = 'application/zip'",
                "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
                "file:content_ref.decryption_key = 'infected'"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_malware_sample_observable_attribute(cls):
        observables = deepcopy(_MALWARE_SAMPLE_OBSERVABLE_ATTRIBUTE)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observables[-1]['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_mutex_indicator_attribute(cls):
        return cls.__assemble_bundle(_MUTEX_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_mutex_observable_attribute(cls):
        return cls.__assemble_bundle(*_MUTEX_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_patterning_language_attributes(cls):
        return cls.__assemble_bundle(*_PATTERNING_LANGUAGE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_port_indicator_attribute(cls):
        return cls.__assemble_bundle(_PORT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_indicator_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_observable_attribute(cls):
        return cls.__assemble_bundle(*_REGKEY_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_value_indicator_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_VALUE_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_value_observable_attribute(cls):
        return cls.__assemble_bundle(*_REGKEY_VALUE_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_size_in_bytes_indicator_attribute(cls):
        return cls.__assemble_bundle(_SIZE_IN_BYTES_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_url_indicator_attributes(cls):
        return cls.__assemble_bundle(*_URL_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_url_observable_attributes(cls):
        return cls.__assemble_bundle(*_URL_OBSERVABLE_ATTRIBUTES)

    @classmethod
    def get_bundle_with_vulnerability_attribute(cls):
        return cls.__assemble_bundle(_VULNERABILITY_ATTRIBUTE)

    @classmethod
    def get_bundle_with_x509_fingerprint_indicator_attributes(cls):
        return cls.__assemble_bundle(*_X509_FINGERPRINT_INDICATOR_ATTRIBUTES)

    @classmethod
    def get_bundle_with_x509_fingerprint_observable_attributes(cls):
        return cls.__assemble_bundle(*_X509_FINGERPRINT_OBSERVABLE_ATTRIBUTES)

    ################################################################################
    #                                EVENTS SAMPLES                                #
    ################################################################################

    @classmethod
    def get_bundle_with_invalid_uuids(cls):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            *_BUNDLE_WITH_INVALID_UUIDS
        ]
        return dict_to_stix2(
            bundle,
            allow_custom=True,
            interoperability=True
        )

    @classmethod
    def get_bundle_with_multiple_reports(cls):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            cls.__identity,
            *_BUNDLE_WITH_MULTIPLE_REPORTS
        ]
        return dict_to_stix2(bundle, allow_custom = True)

    @classmethod
    def get_bundle_with_no_report(cls):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            cls.__identity,
            *_BUNDLE_WITH_NO_REPORT
        ]
        return dict_to_stix2(bundle, allow_custom = True)

    @classmethod
    def get_bundle_with_sightings(cls):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'] = [
            cls.__identity,
            *_BUNDLE_WITH_SIGHTINGS
        ]
        return dict_to_stix2(bundle, allow_custom = True)

    @classmethod
    def get_bundle_with_single_report(cls):
        return cls.__assemble_bundle(*_BUNDLE_WITH_NO_REPORT)

    ################################################################################
    #                               GALAXIES SAMPLES                               #
    ################################################################################

    @classmethod
    def get_bundle_with_attack_pattern_galaxy(cls):
        return cls.__assemble_bundle(_ATTACK_PATTERN_GALAXY)

    @classmethod
    def get_bundle_with_course_of_action_galaxy(cls):
        return cls.__assemble_bundle(_COURSE_OF_ACTION_GALAXY)

    @classmethod
    def get_bundle_with_custom_galaxy(cls):
        return cls.__assemble_bundle(_CUSTOM_GALAXY)

    @classmethod
    def get_bundle_with_intrusion_set_galaxy(cls):
        return cls.__assemble_bundle(_INTRUSION_SET_GALAXY)

    @classmethod
    def get_bundle_with_location_galaxies(cls):
        return cls.__assemble_bundle(*_LOCATION_GALAXIES)

    @classmethod
    def get_bundle_with_malware_galaxy(cls):
        return cls.__assemble_bundle(_MALWARE_GALAXY)

    @classmethod
    def get_bundle_with_sector_galaxy(cls):
        return cls.__assemble_bundle(_SECTOR_GALAXY)

    @classmethod
    def get_bundle_with_threat_actor_galaxy(cls):
        return cls.__assemble_bundle(_THREAT_ACTOR_GALAXY)

    @classmethod
    def get_bundle_with_tool_galaxy(cls):
        return cls.__assemble_bundle(_TOOL_GALAXY)

    @classmethod
    def get_bundle_with_vulnerability_galaxy(cls):
        return cls.__assemble_bundle(_VULNERABILITY_GALAXY)

    ################################################################################
    #                             MISP OBJECTS SAMPLES                             #
    ################################################################################

    @classmethod
    def get_bundle_with_account_indicator_objects(cls):
        return cls.__assemble_bundle(*_ACCOUNT_INDICATOR_OBJECTS)

    @classmethod
    def get_bundle_with_account_observable_objects(cls):
        return cls.__assemble_bundle(*_ACCOUNT_OBSERVABLE_OBJECTS)

    @classmethod
    def get_bundle_with_account_with_attachment_indicator_objects(cls):
        indicators = deepcopy(_ACCOUNT_WITH_ATTACHMENT_INDICATOR_OBJECTS)
        with open(_TESTFILES_PATH / 'octocat.png', 'rb') as f:
            data = b64encode(f.read()).decode()
        patterns = (
            (
                "user-account:account_type = 'facebook'",
                "user-account:user_id = '1392781243'",
                "user-account:account_login = 'octocat'",
                "user-account:x_misp_link = 'https://facebook.com/octocat'",
                f"user-account:x_misp_user_avatar.data = '{data}'",
                "user-account:x_misp_user_avatar.value = 'octocat.png'"
            ),
            (
                "user-account:account_type = 'github'",
                "user-account:user_id = '1'",
                "user-account:display_name = 'Octo Cat'",
                "user-account:account_login = 'octocat'",
                "user-account:x_misp_organisation = 'GitHub'",
                f"user-account:x_misp_profile_image.data = '{data}'",
                "user-account:x_misp_profile_image.value = 'octocat.png'"
            ),
            (
                "user-account:account_type = 'parler'",
                "user-account:user_id = '42'",
                "user-account:account_login = 'ParlerOctocat'",
                "user-account:x_misp_human = 'False'",
                f"user-account:x_misp_profile_photo.data = '{data}'",
                "user-account:x_misp_profile_photo.value = 'octocat.png'"
            ),
            (
                "user-account:account_type = 'reddit'",
                "user-account:user_id = '666'",
                "user-account:account_login = 'RedditOctocat'",
                "user-account:x_misp_description = 'Reddit account of the OctoCat'",
                f"user-account:x_misp_account_avatar.data = '{data}'",
                "user-account:x_misp_account_avatar.value = 'octocat.png'"
            ),
            (
                "user-account:account_type = 'twitter'",
                "user-account:display_name = 'Octo Cat'",
                "user-account:user_id = '1357111317'",
                "user-account:account_login = 'octocat'",
                "user-account:x_misp_followers = '666'",
                f"user-account:x_misp_profile_image.data = '{data}'",
                "user-account:x_misp_profile_image.value = 'octocat.png'"
            ),
            (
                "user-account:account_type = 'unix'",
                "user-account:display_name = 'Code Monkey'",
                "user-account:credential = 'P4ssw0rd1234!'",
                "user-account:user_id = 'iglocska'",
                "user-account:account_login = 'iglocska'",
                "user-account:credential_last_changed = '2020-10-25T16:22:00Z'",
                "user-account:extensions.'unix-account-ext'.groups = 'viktor-fan'",
                "user-account:extensions.'unix-account-ext'.groups = 'donald-fan'",
                "user-account:extensions.'unix-account-ext'.gid = '2004'",
                "user-account:extensions.'unix-account-ext'.home_dir = '/home/iglocska'",
                f"user-account:x_misp_user_avatar.data = '{data}'",
                "user-account:x_misp_user_avatar.value = 'octocat.png'"
            )
        )
        for indicator, pattern in zip(indicators, patterns):
            indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(*indicators)

    @classmethod
    def get_bundle_with_account_with_attachment_observable_objects(cls):
        observables = deepcopy(_ACCOUNT_WITH_ATTACHMENT_OBSERVABLE_OBJECTS)
        with open(_TESTFILES_PATH / 'octocat.png', 'rb') as f:
            data = b64encode(f.read()).decode()
        features = (
            'x_misp_user_avatar',
            'x_misp_profile_image',
            'x_misp_profile_photo',
            'x_misp_account_avatar',
            'x_misp_profile_image',
            'x_misp_user_avatar'
        )
        for observable, feature in zip(observables[1::2], features):
            observable[feature]['data'] = data
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_android_app_indicator_object(cls):
        return cls.__assemble_bundle(_ANDROID_APP_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_android_app_observable_object(cls):
        return cls.__assemble_bundle(*_ANDROID_APP_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_annotation_object(cls):
        return cls.__assemble_bundle(*_ANNOTATION_OBJECT)

    @classmethod
    def get_bundle_with_asn_indicator_object(cls):
        return cls.__assemble_bundle(_ASN_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_asn_observable_object(cls):
        return cls.__assemble_bundle(*_ASN_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_attack_pattern_object(cls):
        return cls.__assemble_bundle(_ATTACK_PATTERN_OBJECT)

    @classmethod
    def get_bundle_with_course_of_action_object(cls):
        return cls.__assemble_bundle(_COURSE_OF_ACTION_OBJECT)

    @classmethod
    def get_bundle_with_cpe_asset_indicator_object(cls):
        return cls.__assemble_bundle(_CPE_ASSET_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_cpe_asset_observable_object(cls):
        return cls.__assemble_bundle(*_CPE_ASSET_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_credential_indicator_object(cls):
        return cls.__assemble_bundle(_CREDENTIAL_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_credential_observable_object(cls):
        return cls.__assemble_bundle(*_CREDENTIAL_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_custom_objects(cls):
        return cls.__assemble_bundle(*_CUSTOM_OBJECTS)

    @classmethod
    def get_bundle_with_domain_ip_indicator_object(cls):
        return cls.__assemble_bundle(_DOMAIN_IP_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_domain_ip_observable_objects(cls):
        return cls.__assemble_bundle(*_DOMAIN_IP_OBSERVABLE_OBJECTS)

    @classmethod
    def get_bundle_with_email_indicator_object(cls):
        return cls.__assemble_bundle(_EMAIL_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_email_observable_object(cls):
        return cls.__assemble_bundle(*_EMAIL_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_employee_object(cls):
        return cls.__assemble_bundle(_EMPLOYEE_OBJECT)

    @classmethod
    def get_bundle_with_file_and_pe_indicator_object(cls):
        return cls.__assemble_bundle(_FILE_AND_PE_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_file_and_pe_observable_object(cls):
        return cls.__assemble_bundle(*_FILE_AND_PE_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_file_indicator_object(cls):
        indicator = deepcopy(_FILE_INDICATOR_OBJECT)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            pattern = [
                "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                "file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86'",
                "file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b'",
                "file:name = 'oui'",
                "file:name_enc = 'UTF-8'",
                "file:size = '35'",
                "file:parent_directory_ref.path = '/var/www/MISP/app/files/scripts/tmp'",
                f"(file:content_ref.payload_bin = '{b64encode(f.read()).decode()}'",
                "file:content_ref.x_misp_filename = 'oui'",
                "file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                "file:content_ref.mime_type = 'application/zip'",
                "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
                "file:content_ref.decryption_key = 'infected')",
                "(file:content_ref.payload_bin = 'Tm9uLW1hbGljaW91cyBmaWxlCg=='",
                "file:content_ref.x_misp_filename = 'non')"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_file_observable_object(cls):
        observables = deepcopy(_FILE_OBSERVABLE_OBJECT)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observables[-1]['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_geolocation_object(cls):
        return cls.__assemble_bundle(_GEOLOCATION_OBJECT)

    @classmethod
    def get_bundle_with_http_request_indicator_object(cls):
        return cls.__assemble_bundle(_HTTP_REQUEST_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_http_request_observable_object(cls):
        return cls.__assemble_bundle(*_HTTP_REQUEST_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_image_indicator_object(cls):
        indicator = deepcopy(_IMAGE_INDICATOR_OBJECT)
        with open(_TESTFILES_PATH / 'STIX_logo.png', 'rb') as f:
            pattern = [
                "file:name = 'STIX.png'",
                f"file:content_ref.payload_bin = '{b64encode(f.read()).decode()}'",
                "file:content_ref.mime_type = 'image/png'",
                "file:content_ref.x_misp_filename = 'STIX.png'",
                "file:content_ref.url = 'https://oasis-open.github.io/cti-documentation/img/STIX.png'",
                "file:x_misp_image_text = 'STIX'"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_image_observable_object(cls):
        observables = deepcopy(_IMAGE_OBSERVABLE_OBJECT)
        with open(_TESTFILES_PATH / 'STIX_logo.png', 'rb') as f:
            observables[-1]['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_ip_port_indicator_object(cls):
        return cls.__assemble_bundle(_IP_PORT_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_ip_port_observable_object(cls):
        return cls.__assemble_bundle(*_IP_PORT_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_legal_entity_object(cls):
        identity = _LEGAL_ENTITY_OBJECT
        with open(_TESTFILES_PATH / 'umbrella_logo.png', 'rb') as f:
            identity['x_misp_logo']['data'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(identity)

    @classmethod
    def get_bundle_with_lnk_indicator_object(cls):
        indicator = deepcopy(_LNK_INDICATOR_OBJECT)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            pattern = [
                "file:atime = '2021-01-01T00:00:00Z'",
                "file:ctime = '2017-10-01T08:00:00Z'",
                "file:mtime = '2020-10-25T16:22:00Z'",
                "file:name = 'oui'",
                "file:parent_directory_ref.path = '/var/www/MISP/app/files/scripts/tmp'",
                "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                "file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86'",
                "file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b'",
                f"(file:content_ref.payload_bin = '{b64encode(f.read()).decode()}'",
                "file:content_ref.x_misp_filename = 'oui'",
                "file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                "file:content_ref.mime_type = 'application/zip'",
                "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
                "file:content_ref.decryption_key = 'infected')",
                "file:size = '35'"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_lnk_observable_object(cls):
        observables = deepcopy(_LNK_OBSERVABLE_OBJECT)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observables[-1]['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_mutex_indicator_object(cls):
        return cls.__assemble_bundle(_MUTEX_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_mutex_observable_object(cls):
        return cls.__assemble_bundle(*_MUTEX_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_netflow_indicator_object(cls):
        return cls.__assemble_bundle(_NETFLOW_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_netflow_observable_object(cls):
        return cls.__assemble_bundle(*_NETFLOW_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_network_connection_indicator_object(cls):
        return cls.__assemble_bundle(_NETWORK_CONNECTION_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_network_connection_observable_object(cls):
        return cls.__assemble_bundle(*_NETWORK_CONNECTION_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_network_socket_indicator_object(cls):
        return cls.__assemble_bundle(_NETWORK_SOCKET_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_network_socket_observable_object(cls):
        return cls.__assemble_bundle(*_NETWORK_SOCKET_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_news_agency_object(cls):
        identity = _NEWS_AGENCY_OBJECT
        with open(_TESTFILES_PATH / 'AFP_logo.png', 'rb') as f:
            identity['x_misp_attachment']['data'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(identity)

    @classmethod
    def get_bundle_with_object_references(cls):
        return cls.__assemble_bundle(*_OBJECTS_WITH_REFERENCES)

    @classmethod
    def get_bundle_with_organization_object(cls):
        return cls.__assemble_bundle(_ORGANIZATION_OBJECT)

    @classmethod
    def get_bundle_with_patterning_language_objects(cls):
        return cls.__assemble_bundle(*_PATTERNING_LANGUAGE_OBJECTS)

    @classmethod
    def get_bundle_with_process_indicator_object(cls):
        return cls.__assemble_bundle(_PROCESS_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_process_observable_object(cls):
        return cls.__assemble_bundle(*_PROCESS_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_registry_key_indicator_object(cls):
        return cls.__assemble_bundle(_REGISTRY_KEY_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_registry_key_observable_object(cls):
        return cls.__assemble_bundle(*_REGISTRY_KEY_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_script_objects(cls):
        return cls.__assemble_bundle(*_SCRIPT_OBJECTS)

    @classmethod
    def get_bundle_with_url_indicator_object(cls):
        return cls.__assemble_bundle(_URL_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_url_observable_object(cls):
        return cls.__assemble_bundle(*_URL_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_vulnerability_object(cls):
        return cls.__assemble_bundle(_VULNERABILITY_OBJECT)

    @classmethod
    def get_bundle_with_x509_indicator_object(cls):
        return cls.__assemble_bundle(_X509_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_x509_observable_object(cls):
        return cls.__assemble_bundle(*_X509_OBSERVABLE_OBJECT)
