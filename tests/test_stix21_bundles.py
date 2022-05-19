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
_EMAIL_OBSERVABLE_OBJECTS = [
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
            "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
            "email-addr--518b4bcb-a86b-4783-9457-391d548b605b",
            "email-addr--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "email-addr--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
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
        "from_ref": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "to_refs": [
            "email-addr--518b4bcb-a86b-4783-9457-391d548b605b"
        ],
        "cc_refs": [
            "email-addr--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
            "email-addr--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
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
        "id": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "source@email.test"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "destination@email.test"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "value": "cc1@email.test"
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "value": "cc2@email.test"
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
            "email-addr--3b940996-f99b-4bda-b065-69b8957f688c",
            "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
            "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6"
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
        "is_multipart": False,
        "from_ref": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
        "to_refs": [
            "email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46",
            "email-addr--3b940996-f99b-4bda-b065-69b8957f688c"
        ],
        "cc_refs": [
            "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6"
        ],
        "bcc_refs": [
            "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6"
        ]
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
        "id": "email-addr--3b940996-f99b-4bda-b065-69b8957f688c",
        "value": "jfk@gov.us",
        "display_name": "John Fitzgerald Kennedy"
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
        ],
        "x_misp_yara_rule_name": "Ultimate rule"
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
    "x_misp_created": "2017-10-13T07:29:00",
    "x_misp_cvss_score": "6.8",
    "x_misp_published": "2017-10-13T07:29:00"
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


class TestSTIX21Bundles:
    __bundle = {
        "type": "bundle",
        "id": "bundle--1dec4c6d-b06a-4f9a-a3e9-7bcdbac4f83a",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "MISP-Project",
                "identity_class": "organization"
            },
            {
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
        ]
    }

    @classmethod
    def __assemble_bundle(cls, *stix_objects):
        bundle = deepcopy(cls.__bundle)
        bundle['objects'].extend(stix_objects)
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
                "user-account:credential_last_changed = '2020-10-25T16:22:00'",
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
    def get_bundle_with_domain_ip_indicator_object(cls):
        return cls.__assemble_bundle(_DOMAIN_IP_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_domain_ip_observable_objects(cls):
        return cls.__assemble_bundle(*_DOMAIN_IP_OBSERVABLE_OBJECTS)

    @classmethod
    def get_bundle_with_email_indicator_object(cls):
        return cls.__assemble_bundle(_EMAIL_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_email_observable_objects(cls):
        return cls.__assemble_bundle(*_EMAIL_OBSERVABLE_OBJECTS)

    @classmethod
    def get_bundle_with_employee_object(cls):
        return cls.__assemble_bundle(_EMPLOYEE_OBJECT)

    @classmethod
    def get_bundle_with_geolocation_object(cls):
        return cls.__assemble_bundle(_GEOLOCATION_OBJECT)

    @classmethod
    def get_bundle_with_legal_entity_object(cls):
        identity = _LEGAL_ENTITY_OBJECT
        with open(_TESTFILES_PATH / 'umbrella_logo.png', 'rb') as f:
            identity['x_misp_logo']['data'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(identity)

    @classmethod
    def get_bundle_with_news_agency_object(cls):
        identity = _NEWS_AGENCY_OBJECT
        with open(_TESTFILES_PATH / 'AFP_logo.png', 'rb') as f:
            identity['x_misp_attachment']['data'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(identity)

    @classmethod
    def get_bundle_with_organization_object(cls):
        return cls.__assemble_bundle(_ORGANIZATION_OBJECT)

    @classmethod
    def get_bundle_with_patterning_language_objects(cls):
        return cls.__assemble_bundle(*_PATTERNING_LANGUAGE_OBJECTS)

    @classmethod
    def get_bundle_with_script_objects(cls):
        return cls.__assemble_bundle(*_SCRIPT_OBJECTS)

    @classmethod
    def get_bundle_with_vulnerability_object(cls):
        return cls.__assemble_bundle(_VULNERABILITY_OBJECT)
