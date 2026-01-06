#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ._test_stix_import import TestSTIX2Bundles
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
        "object_refs": ["user-account--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b"],
        "labels": [
            'misp:name="gitlab-user"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"',
        ],
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'gitlab' AND user-account:user_id = '1234567890']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="gitlab-user"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--746d942a-8a4a-482c-8bb2-88137bb9ef72",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
        "target_ref": "observed-data--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
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
        "object_refs": ["user-account--7ecc4537-89cd-4f17-8027-6e0f70710c53"],
        "labels": [
            'misp:name="telegram-account"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"',
        ],
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "user_id": "1234567890",
        "account_login": "T3l3gr4mUs3r",
        "account_type": "telegram",
        "x_misp_phone": ["0112233445", "0556677889"],
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'telegram' AND user-account:user_id = '1234567890']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="telegram-account"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f8117c4c-1a27-48e2-9df4-bbce247b3783",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "target_ref": "observed-data--7ecc4537-89cd-4f17-8027-6e0f70710c53",
    },
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'facebook' AND user-account:user_id = '1392781243']",
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
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--7db8539b-3a18-4ba3-9fac-d38d3aa03bdd",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "target_ref": "observed-data--7d8ac653-b65c-42a6-8420-ddc71d65f50d"
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5177abbd-c437-4acb-9173-eee371ad24da",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'github' AND user-account:user_id = '1']",
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
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--d88cf4b1-e4ed-46c6-9a2d-af8bafda3e8a",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5177abbd-c437-4acb-9173-eee371ad24da",
        "target_ref": "observed-data--5177abbd-c437-4acb-9173-eee371ad24da"
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'parler' AND user-account:user_id = '42']",
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
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--2bb5818f-2e44-43a2-b0de-1d69516b48cb",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "target_ref": "observed-data--7b0698a0-209a-4da0-a5c5-cfc4734f3af2"
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'reddit' AND user-account:user_id = '666']",
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
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--601caace-838b-470d-b5b7-9e0bf59782e8",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "target_ref": "observed-data--43d3eff0-fabc-4663-9493-fad3a1eed0d5"
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'twitter' AND user-account:user_id = '1357111317']",
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
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--c24d40c6-edda-4cb4-9afe-75b63789b974",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "target_ref": "observed-data--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb"
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_login = 'iglocska']",
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
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--127637c9-7a83-4e0c-8d1f-666ad1cc3fa2",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
        "target_ref": "observed-data--5d234f25-539c-4d12-bf93-2c46a964451a"
    }
]
_ANALYST_DATA_SAMPLES = [
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f7ef1b4a-964a-4a69-9e21-808f85c56238",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '194.78.89.250']",
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
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--e6039f2f-d705-41d0-859d-89845546cd7b",
        "created": "2024-06-12T12:49:45.000Z",
        "modified": "2024-06-12T12:51:41.000Z",
        "explanation": "Fully agree with the malicious nature of the IP",
        "authors": [
            "opinion@foo.bar"
        ],
        "opinion": "strongly-agree",
        "object_refs": [
            "indicator--f7ef1b4a-964a-4a69-9e21-808f85c56238"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Opinion\""
        ],
        "x_misp_opinion": 90
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--76fd763a-45fb-49a6-a732-64aeedbfd7d4",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "network-traffic--76fd763a-45fb-49a6-a732-64aeedbfd7d4",
            "ipv4-addr--76fd763a-45fb-49a6-a732-64aeedbfd7d4"
        ],
        "labels": [
            "misp:type=\"ip-dst\"",
            "misp:category=\"Network activity\""
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--76fd763a-45fb-49a6-a732-64aeedbfd7d4",
        "dst_ref": "ipv4-addr--76fd763a-45fb-49a6-a732-64aeedbfd7d4",
        "protocols": [
            "tcp"
        ]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--76fd763a-45fb-49a6-a732-64aeedbfd7d4",
        "value": "8.8.8.8"
    },
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--31fc7048-9ede-4db9-a423-ef97670ed4c6",
        "created": "2024-06-12T12:52:45.000Z",
        "modified": "2024-06-12T12:52:45.000Z",
        "content": "DNS Resolver used to resolve the malicious domain",
        "authors": [
            "opinion@foo.bar"
        ],
        "object_refs": [
            "observed-data--76fd763a-45fb-49a6-a732-64aeedbfd7d4"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Note\""
        ],
        "lang": "en"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--eb49356e-d709-4e63-b8a2-f8c5cc54f38f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[file:hashes.MD5 = '0cdc9b1b45064e6315f83b150c0fc0eb' AND file:name = 'bin.exe' AND (file:content_ref.x_misp_filename = 'bin.exe' AND file:content_ref.hashes.MD5 = '0cdc9b1b45064e6315f83b150c0fc0eb' AND file:content_ref.mime_type = 'application/zip' AND file:content_ref.encryption_algorithm = 'mime-type-indicated' AND file:content_ref.decryption_key = 'infected')]",
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
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--74258748-78f2-4b19-bedc-27ec61b1c5df",
        "created": "2024-06-12T12:52:48.000Z",
        "modified": "2024-06-12T12:53:58.000Z",
        "explanation": "No warning from my antivirus",
        "authors": [
            "john.doe@foo.bar"
        ],
        "opinion": "neutral",
        "object_refs": [
            "indicator--eb49356e-d709-4e63-b8a2-f8c5cc54f38f"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Opinion\""
        ],
        "x_misp_opinion": 60
    },
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--dc14f700-6822-46bd-9b65-fb2703cf707f",
        "created": "2024-06-12T12:51:16.000Z",
        "modified": "2024-06-12T12:51:16.000Z",
        "content": "Should be the Putty agent",
        "authors": [
            "john.doe@foo.bar"
        ],
        "object_refs": [
            "indicator--eb49356e-d709-4e63-b8a2-f8c5cc54f38f"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Note\""
        ],
        "lang": "en"
    },
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--44ceb474-6493-48de-b753-bbd0470e0e54",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2024-06-11T11:34:42.000Z",
        "modified": "2024-06-11T11:34:42.000Z",
        "abstract": "Summary of the case",
        "content": "A victim reported a malicious file @[object](eb49356e-d709-4e63-b8a2-f8c5cc54f38f)\nThis file was downloaded by the victim via the IP @[attribute](60c2c930-d0ab-49b1-986c-3d2ec60ba5ac)",
        "object_refs": [
            "indicator--eb49356e-d709-4e63-b8a2-f8c5cc54f38f"
        ],
        "labels": [
            "misp:data-layer=\"Event Report\""
        ]
    },
    {
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--0178d298-4e02-4471-a115-8f3e381fe530",
        "created": "2024-06-25T11:46:25.000Z",
        "modified": "2024-06-25T11:46:25.000Z",
        "explanation": "Event though it is a concise report, I agree with it",
        "authors": [
            "anonymous@foo.bar"
        ],
        "opinion": "agree",
        "object_refs": [
            "note--44ceb474-6493-48de-b753-bbd0470e0e54"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Opinion\""
        ],
        "x_misp_opinion": 68
    },
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--bbd17601-425f-4dd5-82ed-0b18115bee98",
        "created": "2024-06-25T06:33:45.000Z",
        "modified": "2024-06-25T06:33:45.000Z",
        "content": "Straight to the point Event",
        "authors": [
            "reporter@gfoo.bar"
        ],
        "object_refs": [
            "grouping--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
        ],
        "labels": [
            "misp:context-layer=\"Analyst Note\""
        ],
        "lang": "en"
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
        "object_refs": ["software--02782ed5-b27f-4abc-8bae-efebe13a46dd"],
        "labels": [
            'misp:name="android-app"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--02782ed5-b27f-4abc-8bae-efebe13a46dd",
        "name": "Facebook",
        "x_misp_certificate": "c3a94cdf5ad4d71fd60c16ba8801529c78e7398f",
        "x_misp_domain": "facebook.com",
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="android-app"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--083173fd-5fce-4b13-b413-bf10aa781ee5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--02782ed5-b27f-4abc-8bae-efebe13a46dd",
        "target_ref": "observed-data--02782ed5-b27f-4abc-8bae-efebe13a46dd",
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
        "object_refs": ["autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="AS"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "number": 174
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="AS"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
        "object_refs": ["autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f"],
        "labels": [
            'misp:name="asn"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "number": 66642,
        "name": "AS name",
        "x_misp_subnet_announced": ["1.2.3.4", "8.8.8.8"]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[autonomous-system:number = '66642']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="asn"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--36414951-fe93-4021-8234-9d7fae390de9",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "target_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f"
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
            'misp:type="attachment"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="attachment"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    }
]
_ATTACK_PATTERN_GALAXY = {
    "type": "attack-pattern",
    "spec_version": "2.1",
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
    _ATTACK_PATTERN_GALAXY,
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation",
        "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
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
        "name": "BISCUIT",
        "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
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
        "target_ref": "attack-pattern--e042a41b-5ecf-4f3a-8f1f-1b528c534772"
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
    },
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--11111111-1111-1111-1111-111111111111",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "Automated Exfiltration Mitigation",
        "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network",
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
        "name": "BISCUIT",
        "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
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
            "indicator--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
            "relationship--600e528a-1967-4489-a604-a04af707490c",
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[autonomous-system:number = '174']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="AS"',
            'misp:category="Network activity"',
            'misp:to_ids="True"',
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "target_ref": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
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
        "name": "BISCUIT",
        "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
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
        "object_refs": ["autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f"],
        "labels": [
            'misp:name="asn"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "number": 66642,
        "name": "AS name",
        "x_misp_subnet_announced": ["1.2.3.4", "8.8.8.8"]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[autonomous-system:number = '174']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="AS"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5b23c82b-6508-4bdc-b580-045b0a00020f",
        "target_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f"
    },
    {
        "id": "observed-data--2972c3a2-dda3-4de7-aca1-e96cf7ce5544",
        "type": "observed-data",
        "labels": ['misp:type="AS"', 'misp:category="Network activity"'],
        "number_observed": 1,
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "object_refs": ["autonomous-system--2972c3a2-dda3-4de7-aca1-e96cf7ce5544"],
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
            'misp:type="domain"',
            'misp:category="Network activity"',
            'misp:to_ids="True"',
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
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
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="domain-ip"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "BISCUIT",
        "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
        "is_family": True,
        "labels": ['misp:galaxy-name="Malware"', 'misp:galaxy-type="mitre-malware"']
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
        "object_refs": ["software--3f53a829-6307-4006-b7a2-ff53dace4159"],
        "labels": [
            'misp:name="cpe-asset"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--3f53a829-6307-4006-b7a2-ff53dace4159",
        "name": "Word",
        "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
        "languages": ["ENG"],
        "vendor": "Microsoft",
        "version": "2002",
        "x_misp_description": "Microsoft Word is a word processing software developed by Microsoft."
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--3f53a829-6307-4006-b7a2-ff53dace4159",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[software:cpe = 'cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="cpe-asset"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--ea9e373b-57f1-46bd-9b65-aa845865817b",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--3f53a829-6307-4006-b7a2-ff53dace4159",
        "target_ref": "observed-data--3f53a829-6307-4006-b7a2-ff53dace4159"
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
        "object_refs": ["user-account--5b1f9378-46d4-494b-a4c1-044e0a00020f"],
        "labels": [
            'misp:name="credential"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"'
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5b1f9378-46d4-494b-a4c1-044e0a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:x_misp_text = 'MISP default credentials']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="credential"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--49fd4899-8273-4e23-9e70-d92c507fb3bf",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5b1f9378-46d4-494b-a4c1-044e0a00020f",
        "target_ref": "observed-data--5b1f9378-46d4-494b-a4c1-044e0a00020f"
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
    "x_misp_description": "Milk in tea",
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
        "object_refs": ["domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="domain"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="domain"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            'misp:type="domain|ip"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu",
        "resolves_to_refs": ["ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "149.13.33.14"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="domain|ip"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        ],
        "labels": [
            'misp:name="domain-ip"',
            'misp:meta-category="network"',
            'misp:to_ids="False"',
        ],
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "149.13.33.14",
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--876133b5-b5fc-449c-ba9e-e467790da8eb",
        "value": "185.194.93.14",
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
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac337df-e078-4e99-8b17-02550a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[domain-name:value = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="domain-ip"',
            'misp:meta-category="network"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--005827a3-1015-474d-bd67-79d593129cf1",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac337df-e078-4e99-8b17-02550a00020f",
        "target_ref": "observed-data--5ac337df-e078-4e99-8b17-02550a00020f"
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
            'misp:name="domain-ip"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--dc624447-684a-488f-9e16-f78f717d8efd",
        "value": "circl.lu",
        "resolves_to_refs": ["ipv4-addr--fcbaf339-615a-409c-915f-034420dc90ca"],
        "x_misp_hostname": "circl.lu",
        "x_misp_port": "8443"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--fcbaf339-615a-409c-915f-034420dc90ca",
        "value": "149.13.33.14"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[domain-name:value = 'circl.lu' AND domain-name:x_misp_hostname = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="domain-ip"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--5d2dcfac-c0c1-418c-af91-028b8776bdee",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
        "target_ref": "observed-data--dc624447-684a-488f-9e16-f78f717d8efd"
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
            'misp:type="email-attachment"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-attachment"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="email-body"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "is_multipart": False,
        "body": "Email body test"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-body"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            'misp:type="email-dst"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--518b4bcb-a86b-4783-9457-391d548b605b",
        "is_multipart": False,
        "to_refs": ["email-addr--518b4bcb-a86b-4783-9457-391d548b605b"]
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "dst@email.test"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-dst"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
        "object_refs": ["email-message--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="email-header"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-header"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["email-message--f3745b11-2b82-4798-80ba-d32c506135ec"],
        "labels": [
            'misp:type="email-message-id"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--f3745b11-2b82-4798-80ba-d32c506135ec",
        "is_multipart": False,
        "message_id": "1234"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-message-id"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--3a763477-03b7-53c8-b6f8-0e794a79ba28",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f3745b11-2b82-4798-80ba-d32c506135ec",
        "target_ref": "observed-data--f3745b11-2b82-4798-80ba-d32c506135ec"
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
        "object_refs": ["email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="email"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "address@email.test"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            'misp:name="email"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--5e396622-2a54-4c8d-b61d-159da964451a",
        "is_multipart": True,
        "from_ref": "email-addr--f5ec3603-e3d0-42d7-a372-14c1c137699b",
        "to_refs": ["email-addr--aebfd1b3-24bc-4da5-8e74-32cb669b8e46"],
        "cc_refs": [
            "email-addr--1a43d189-e5f6-4087-98df-b2cbddec2cd6",
            "email-addr--efde9a0a-a62a-42a8-b863-14a448e313c6"
        ],
        "bcc_refs": ["email-addr--3b940996-f99b-4bda-b065-69b8957f688c"],
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5e396622-2a54-4c8d-b61d-159da964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[email-message:to_refs[0].value = 'jdoe@random.org' AND email-message:cc_refs[0].value = 'diana.prince@dc.us' AND email-message:cc_refs[1].value = 'marie.curie@nobel.fr' AND email-message:bcc_refs[0].value = 'jfk@gov.us' AND email-message:from_ref.value = 'donald.duck@disney.com' AND email-message:body_multipart[0].body_raw_ref.name = 'attachment1.file' AND email-message:body_multipart[0].content_disposition = 'attachment' AND email-message:body_multipart[1].body_raw_ref.name = 'attachment2.file' AND email-message:body_multipart[1].content_disposition = 'attachment']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="email"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--dd033127-0059-4994-9c1d-5a9b3830fcd9",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5e396622-2a54-4c8d-b61d-159da964451a",
        "target_ref": "observed-data--5e396622-2a54-4c8d-b61d-159da964451a",
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
        "object_refs": ["email-message--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"],
        "labels": [
            'misp:type="email-reply-to"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-reply-to"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--a3444188-4046-4544-95ca-11e0da5216ce",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "target_ref": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
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
            "email-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        ],
        "labels": [
            'misp:type="email-src"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-src"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["email-message--34cb1a7c-55ec-412a-8684-ba4a88d83a45"],
        "labels": [
            'misp:type="email-subject"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "is_multipart": False,
        "subject": "Test Subject"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-subject"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0b488954-0d5a-4ea9-b3e0-23b8839ba94f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "target_ref": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
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
        "object_refs": ["email-message--f09d8496-e2ba-4250-878a-bec9b85c7e96"],
        "labels": [
            'misp:type="email-x-mailer"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="email-x-mailer"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f6ca586b-8e47-4457-b8f4-28b3f258d9de",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f09d8496-e2ba-4250-878a-bec9b85c7e96",
        "target_ref": "observed-data--f09d8496-e2ba-4250-878a-bec9b85c7e96"
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
_EVENT_REPORT = [
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--c2f59d25-87fe-44aa-8f83-e8e59d077bf5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "DNS Server",
        "description": "Adversaries may compromise third-party DNS servers that can be used during targeting.",
        "labels": [
            "misp:galaxy-name=\"Attack Pattern\"",
            "misp:galaxy-type=\"mitre-attack-pattern\""
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1584.002"
            },
            {
                "source_name": "url",
                "url": "https://attack.mitre.org/techniques/T1584/002"
            }
        ]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f9b286a9-3ed6-4ace-a60c-a5fe6529a783",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '8.8.8.8']",
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
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f715be9f-845f-4d8c-8dce-852b353b3488",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--f715be9f-845f-4d8c-8dce-852b353b3488",
            "artifact--f715be9f-845f-4d8c-8dce-852b353b3488"
        ],
        "labels": [
            "misp:type=\"attachment\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f715be9f-845f-4d8c-8dce-852b353b3488",
        "name": "google_screenshot.png",
        "content_ref": "artifact--f715be9f-845f-4d8c-8dce-852b353b3488"
    },
    {
        "type": "artifact",
        "spec_version": "2.1",
        "id": "artifact--f715be9f-845f-4d8c-8dce-852b353b3488",
        "payload_bin": "iVBORw0KGgoAAAANSUhEUgAAAgkAAAAzCAYAAAAdHJsaAAAABHNCSVQICAgIfAhkiAAAABl0RVh0U29mdHdhcmUAZ25vbWUtc2NyZWVuc2hvdO8Dvz4AABpmSURBVHic7Z3pb1xXlth/99XOWlgkq1hcRIkl7ou1WLYkS7It2S3b3U5j3En3jDEz3bMAQYAgwADzDyRfEwRIvkwDQTrdSLqRyQTTSzzt8b7Istu2LEu2LIkSRYqbuBZZLJK1L+/lA0nxVbFIVnEploz7A+oDi7fevee9+84999x7zxH0nNSQSCQSiUQiyUHZ7wZIJBKJRCIpT6SRIJFIJBKJJC/SSJBIJBKJRJIXaSRIJBKJRCLJi3G/GyCRSCSS7WKg8/lX+dN2E2LTcipDl3/NL25GkDvVJcVQnJFgjUFNFBwpMKmAgKQJlmwwVwHJzbtp2SHlKW++bfJ8KxGY7G4avVV4nDZsJgMikyIajxKcm2V8LkJCjkoSySNLAUZCBpqmoSsA3gQbmquaAaZq4HY9TFp2tZG7i5RHyiPZMQY7/s5unuo+TJvHtqEiURMLDA7c4+qtfvrmknIWK5E8YohN4ySYInBmAJoSRVzSAPcPwhUvpHfewF1FyoOUR7IzBPb6Hr5/4RjdlcYtXNxraGqc8Ttf8NtPBpmRz2lXEUIgxPonUX3ku/y7p7wYALncINkuG3sSjBG4cAdqMzn/EBCzQMwAqGBPgEXV/T8Dh4fBosGlWlApD6Q8K0h5JNvFQE37WX5y/jDVhvX/1dDIpDNgMGLMGbOEYuVAZzut1+8zsyiHqd1E0zQ0LfeeClR5myW7wAZGggY9QzkKW8BEPVyvg3n9z1TwBuHxUfCm137fOAbtLrhj3aOmF4OUR8oj2RkCR/NpfnzhMNW6M1GaGmWs/w5X7o5yP7DIUkoFYcBW4cBXf4DOw4c55q/BLs9RSSSPJPlfXfM8tEd1XwgY9cMHB3IU9solAh54txNm9NOLDHRNQ54ZR8mR8kh5JDtCOFv5o/Ot1Og0RmZplNd/8zt+9sENvp4ILRsIAFqGWGSB4YFbvPn27/mv/3iJyw8i5PqIJBJJ+ZPfSPCGwKz7O2OH6x42XczKVMB1b3aZigWoKgOfl5RHyiPZAVa6Tz1Oh21tDUGLj/PG7z/k88BWmxE14nNDvP366/zqy2kicjlIInmkyG8kVMazd5UvVkK4gKsFK0G/50wkwVEGWkHKs4yUR7INlJpOnm2xrT0iLcnA559yJVTEvVajDFy9xtdhacRJJI8SefYkaCtn0nXEzJvP6lZRTRATYF0trIFRZX99wFKeh0h5JEVj4FB3Gz7ddEJdvMelu+GS7ZJXTHZ8Pg++SgdOixGFDMl4lOD8HA9mFojs0jpGSepRrHjrajlQ7cJpUdDSCRZDQUYnZplPPaoGlMDsqMqKlUEmSTSyxEwgwHgo8WguNQkjDncNjTUuKu0WrEYFLZ0iGl0iMDvHZCjGTh7Z3vc3E9UNBzjsdVBBkmBggnsTS1nzKoO1Cv9BH3UOMyIVZWZynMHZWNZBsTxGgoBkjoPBoC7P9La8IVqOflYgsd8KW8qzhpRHUiSGWnqbK3QuR5XAwCBjJdD6lupmzp7o5Qm/B+cGj1VNLjEy0MelL+8yGN5eo0pSj2Kn5ejjXDzqp8GmrDs6qqWWGLz5Ja9fHWZWO8iP/uo5jphW6l64yc/+z1XGys1Jptg40N7D070ttHs3ipWhEg2Oc+2rr/iof47YI2AHGR11HD/SzROtjdTbDRsc89VIhmfpH7jH598MMlxEn9j9/mbl8Zd/xA8OLl8sM32Vn76zwImLZznts2a9u+GJb/i/b11nKG7A0/4Urz7dQq1Z6GRMMzd4hb9/v5/pFUsh/3OdrwAtvOYCdkWXFya2aqslCnZdL8jYIVgG25qlPMtIeSRFolTX46/QqUktwsBoaI9PmpppfOwcf/LUQaq2sPkUsxN/90maW1u5eukD/nlgqYhwGaWpR1jruPDieZ5tsG6YLEeYnLQef5Z/7XPxy7cWCpZgvzC5/bz4/GmerLVskQBIoaK6iXPPNXK07Sv+4d0bjMRL1MhiERaaHnuKf3myGY9py8KYHV56j3np6e3m8muv8c70Vm9Fifq10cOzLx3jMU9uHBMFR8MRXj2/xM9v1fDqhVY86x6ekZqW07waXuCnf5gmxUZ7EgI1ENZd3joPB1NbtEyDlkD2zG7cC5ECBdtLpDxIeSTbwV7rzT7ymJ7jwdxemggG6o4+x0/Orlek6XiY6ZkADwIhFpNqlqNJmKt54vkX+UGrvcCsdSWqx1DN2Ref43yOgaBpGaKLISYCQQLh5Io9LKhoOMYfP9WArSAZ9gezt5c/e+UZTuYYCJqaYjE0z8TMLFOhCPGsbqLgbDrOj793jKYtB+B9QNjpfua7/NXZ9QbCslxBxqeX+8R8LJ1lJAuDFceWQV9L1a/BUNPMEY+RTCzE6MQ0k+GU7pqCiuYn+IvnOqhRQE0sMT4xxYMF/ZKQQk1HJ+0rMuX3JGSc8HUVnA0uz+5EGp4cgFgrTOV7wiocGoEjut1mcTdcry5QrD1GyiPlkWwDBU+1K2s2oi2GmN3DpQaT7yg/PFWH3nmRCN7n/U+u8+X40loeCMWCr7mbF8700uZcdgkLxcFjz5xlZOYdrmwRsKk09RhoPHGO5xvMuk2fKab7r/HPVwcYWlxV3goVNYc4d+4kZxtsuDvacZdpWhLh8PPKSyc4bFtzUWfCk3z+5dd8NjDDfHJt+FRMDg619fKdkx002QQCgcV3hB89NcNPP5qgfBwKRg48eYF/1e1mTdtoJIIjfHLtFteGZ1nI2nygYK300tnRxbneQ9Sa118xl1L169W2R0ev8D/e6luObqpU0PXMS7za5Vo2NIQVZ4VGfOIav3jjBhNJAAv+My/xk6NVGAFhqafdZ+DWaAYDtY3/IW89oUogDL7ksuI2JMEfgNoEVKTAHoeqCDTNwfFh6Fpa80tE3fBhC4TKyPUr5ZHySIrERHPPMXrca/c1MzvIB/1BtvLzbAvh5OTzT3Oscm3NPhX4hl++9hnfzCezV5+0DJH5KW7eX6TKfxCfZXnQEkYHjdYg14YWNnbPlqge4WjjB8+143k4c0wxcf1dfv7xMIGEfi6qkYqFGBwYJ+Hz05YT7lpLzHDt5gTFBaoU2OraONW0OgPVCI328dXMDp6cqODohec571vNOKkRm7zBr/7pE76YDBPPZDdQU5OEAg+4MRTG4z+I17xsKFg9VaSH7zFcJhsUTL7j/PkFP5UPb3qGuf5P+Pkb17k9GyWxznGmkU5EmBof5mrfBDGXF8vsAP0LG8iz5/3NSH17D12VK++pFuHqhx/z1WqH0VLMzRto62lYk1GLcu3SR3w5v9rmDAvzgsO9B6hSAKGghYa5NhnfLMGTAb7pgNAEPD4NzgyIDNQHlj/5SFphsB5uerOPppUFUh4pj6QohAW7LXtKm4nHSe5RdYqnjSfr1gZITQ3y8aWvGN7k2arhYV7/uBH/d9tWFKDAfriT3s/H+GKD45alqUdQ29GJXzfLTAdu8psvpjeeQWdCfHbpK7r++BT+MnTJG309nG+2Prxvavg+v3vrOkOxzX+XXhjkn/7QSPPFwzgECKWKE90+Pr48uTfGZjEIO0ee6KRWN7+IT1zjf38wyGwBq2pqPMCnb7+J2bhx4VL161W0zDzjwez2aEtBphMaTSvvs6bO8yCQ7RLUoiGmYxp+hwAElU47gtBWyxwKjB2A17vhjnPzuPhpC9z3wWBVGStsKY+UR1I4RsxZ0wiNVDqzR0cfFXz+pqyNVKmxPq4Etl7biI/e5qpun4Qw+ug+aCW/x75E9YhKOv1u3ZaZFPdu3GVmi4FHWxzk85FEGSZhMtHSdVgXcTPNyPXr9G1hIKwSHe7n5sPBTeA81ERDGTj+lEo/TxwwZQ3gn37St+VzyiZDckO3Van6tY5EhKV11leMpaiuV8UjLOSW0WIsxdaekaXChpmtUkUrSeh4AD1zurPoG2BMQOfIcvnRRviijjJadFpGyiPlkRSOUDDkKHJV3Ux7Cly9L/K3T9dtHKlCDXHpN6/xbiDnOsJKU51+/0OGseEHhe1D1RboH1nkgse9Musx0FjvwXh7bP1MtUT1CGstzbodn1pmhrtj8QIG/yRDozOkW5soK2eCwUunboDS0tPcuF9ErIzMHCMzaU45lwdkxe6h0SEY2ddkXwJn0wHq9KHGp+5xbTc35paqX+t/lkyuV4VailhSXyaRR12miOvKCJMJi9jMSDCH4dl74NM1Z7EK+rwwZYeocdkd7IhCwxx0zYJNW/7u0ChUR+FdP0TKZAeOlEfKIykOTSWToy8VZY+mf6ISn1sXP0ANMz5b6IxaJRCYI4mb1fRe5qoq3GKMwLrkiKWpR3G7s2aP2uIcUwV6vOJzQYJqU1YAq/1GqfTSYNWF5V6YZbwoozzDwlIMjZVZu7BT7RQUudFilzHQ4KvWGbQqM2OTu9ukUvVrHVo6Qzr3/1qGtG7PiJbJV0Ylo08dajBgYCMjQcThbD/4Vn0oAkaa4VMv2bsmjBByLX/ue+CZe1C7UsA5C+ds8E79/qfvlfJIefYNgd3np8dr2dpNiMbixAB9wcJP+u8tGVJZTREYjRsFl9khxgpcukEILcL8UuEPMrMUZkEF68rAqlRU4BSsV6Ylqsdgt2PXVaNGln9XCFokwpIGvoJbtfcoLlfWUVil5ij/9t8c3f4FhQWbeZ8NelFBjUu/STTNTHBpd9VHqfq1Hk3NI4NGlhNQzVdGzS6jbGYkHBqDBp12WKjLo7BziDvh8iF4eZCHZo9nEg55YGifHWdSHinPviFw+4/y8vHKAs45Zxi8NMKdYLo81qS1OOF4dkuMFgsmNno0Gonpft79bHxNVmGn7WgHzdbNBwRhNpOlS7Vklnt0y6YmctynOdcrdT1msynbmEomC946oyWTxMuiA6xhtlq3WJsuFoHBsN9GgoUKfXwDLU54l09clKq/Zf8ovwxaIWWygjQsHzRbr7dEAtpDuoQ7Ctz1ba6wV4lVw6B17W+RBn+ogB/uIVKeNaQ8kqJIs7iU7RoVKzOZjUgE7vPx9W/4aPXz1SAPChkdFSVbGamZ4uL9q2pWeaEYUPK1s0T1CJH9paZpRRh+xZQtDYbczSnfChSMekNFy5De7RggperXe8h649C0BNW6LqraYKbQmZmAKRd067L6eZbA4N06xO5eIeXRIeWRFIPG3PwiKhUP120VVyXVBpaDtOwmue7PFVdnwShKVnlNzaDmG2lLVE86k90BhcGIkcJsXxQDxjLbWpPJ2pyiEb3zHv/pgweP+GumrqzTr9xsYcC426lfStWv95D1RoIjnh3qVjNBtIgeG13J4Lf6E2MSLEB0B63cCVKebKQ8JUZl/LPf8u8/2+92bAeNcGCWkFZHzaoeNVXT6Fa4U8gh8mJqynGxC2HGZgYKPGInLBas+i82cNmXqp5ULE6KNQUrbFYqBAUtI6yWLSeS8ThpVuURmCxmjDzitriWIJqVat6K07a7N75U/W0vWe9DMuU+dlFY2t5V1pVVwbiPzjMpTzZSHkkRZOYmsyPjKZUcbrTv/ubFdJTFLG1qp8pZuIvb4HRQqSuuRqMs5esGJapHXVpiXmdHKS63LsbA5iiuSqp34QbnLlqIHVxTXVzMksfgqlyOzPcoo0WZW9Tv/zHirXEWnCOhIErVr/eQ9a3N5HwlkstHzQrFliJbgyiQ3kezWMqTjZRHUgzpaW6P6M/3KzS2+fHu9i3WFpgO6ZLbKA4aPYWcCFluk9dbgz6EfnI+RChfNypRPerCLJOJtX8IS3bchI0ReHzeXfAkaKRzAl+ZTLlZAQtHXZhlQi+Puw6//VF/zzJMTgezEhvVHqjHtZtilapf7yHre+2q+/ZhiTh4CnUqaeAJZyvtlGUbEfFUaAhAa87Hs40gnmUhjwHPwTZOdLXrPm085rMV/9KWhTzftucj2Zg0g30DWSFqDZ4Ozh4y7643QYszNrWo6woGmvwHsBfyW1FJ+yGXTpllmJgM5F//L1U9mQAD47rse4qLnjbP1icElCp6WtzFrVtvQCwa1bVN4K7cwSw5M8PdsbVNrMLg5fHOql1pZ+Hsoh4FQGNx7AFT+r5d186J9fmTt0+p+tsesv5uxBzZaXvJQFuAgp6CIQItOYvBs85tLFxloGsYTg/pPsPQvI2QemUhj5nmI6d55fyZrM8Lra7iX9qykOfb9nwkm5GZ6ePyqO6Ug7Bz7OyTdOxqPmOV6aEx9MHuTAe6OOnZehiyHuzmCZ0vX0vPcHt0o+iGpaonyb3+EdbC7Auqux7nSfdmb7zA1XqUkwV5HLYmMxfUhRcW2BoP0LTtc4wpBvqGdLNYBd+Rk5yu3o6ZIDBsa4v+LurRFdSFIa4+WDPmhFLFU2e6snI5bM1mGx5L1d/2jvW3QquA4Zy33zsBxxY3V9wiBSeGwKUTQTPCfffutHS7SHmWkfJItosW5canXzOc1C06uNr44cun6HJuoewMJiwFjiPq7D2+mErrFHY1Z88f45Bl498o9kO8fK5F5yLWiA7d4ZtNkuCUqp7E2C0+C6y5/IW5josvnqI775q0oKL+GH9y7iC75cXXlia4F1xzdSvOFi4ezXZfF0Nq8iYf6PJKCHMdF797jserCrU8DLjq23np5T/iT3v2YF/LdtAi3Lh6JytXg6Xhcf7suRY8BYglTFUcP3+RFzZJRFGq/rZX5EkVLSBkAv88a8HDNagNQo0KESvEdG+9yIBvDk4PwqEcP+9sI1yvLG4jGgAqHJ4CZ067Zj0wscmdzUs5yGOiob2bzsrsjhSfHuCzsUiRlysHeb5tz0eyFVp8lqFIFb1+N5YVxWW0e+ntaqbBAqlknEg8uRLqVWCyVdLc2s2LF05ytFIXpVGLM9J3l/vRfA8pyfSCme6O2ocDpcHuo+egk9RCkJklXVpdxYLP/xivvHCSHtfa9bXkNO+8d43hTZ1aJapHizMxZ6C9vY5Vu8Bg89DbcYg6q4KiGDBb7XhrGzh6/CSvnGmh1iRIz80yY6nAsZr5d1upogESBFUvJ5pdK0cqDbga/HRUmxDCiK3CQZXLSfXKp8qUZiG2WSCvFNNTMXytq2mfQbFU0dnRTIM5TXgpzGIiJwGYYqbaW09XZy8vnD/Hy8eaOVRpJjzWx/XpYvOJ7qYeXUONBJg0NPJYw+pRXwVbzUGO+6swJCPML8Vy0kULzA4PHd3H+cHF05yqNxEYuMWdjVJF73l/y04VrUUmuHJnJueAVyFlDNS19dK94u3SolNcvT29wRJZogo+qYPzkzrFrULjxPInZYKYEYQKtmT+3eSR6uVrlEOIXCnP+mtIeSRFoRHqv8yvLAZ+fObAw0FPmCrpPHaazmOgaSrpdAZVMWA2KHlnisn5SUbDGz+k1NRX/PqKl7885WP1NJqlpoXvfb+FF+JLzC7GSQkTrkoXLnN2HZoa4dblj7lSwM6uktUz8zX/8FElf32++eEudWFx033sJN3H1pfXUrN8dPk23pefoW7HC/4ai/1XeKfVw79oWk7OJISZupYjfL9lfen08GX+4xuDm+ZJ08KD/PZNG7bvncBvWzYUhMlF5/GzdB4/QzIWZj4cJ6kasFgtOO0VWI2iPLwGG5Jm7Iv3+bXtIj/sdq+oIIGlupnnvtPMBTXJ0mKYxUQaTTFhtztwV5jW3PAFWCel6m97wcY+kukmeL8JwnmKmFLgioEzkUdhC5itg3dactaa9xkpzwpSHsl2STP5zfv8tzduMBhR1+lGIRRMJhOWPAaCpiUYv/0J//13n9O/6RnxNBPX3+N/fTpGKGdvidHqpK7WS5PXTWWuIk3Nc/2Dt/l1f7hAO7FU9agE737Ez966yXB0/T3LKhmb5vKb7/HhTM5sXtuBc0xd5It33uPt0ciubXhLzNzkl7+9xKdTsZztPwKzzYnP66XJV01tpR1bHgNBy8QIRcts45AW4fZHb/CLPwwzm7P/WihmXO5qDvhqafJWUa03EAAtkyC85WbpUvW33WfzVZdAPfy+CtqnoDUIrk26maZA0A1362HIXp4uXymPlEeyQ1QWRq/xP/9+gI6eXk53NdPsNm+4y11NLjE6NMCVG3e4NZsoUNElefD1e/zdAz9nT/TyRHMNjg0q0FJhRgbv8NGXfdxbLHbgKVU9KqHhq/x84h4dnR0c9dfTVOPEYVbQ0gkW54MMjwxy5dYw4zEVDEp26N1MZkcDvJYI8PHr/49+fzunOg5x2OfGbTNhEIXtD85HemGYN343wbXDnZzpaaW73vUwCVE+1GSYiYkJ7o2McHNwkplEGbr8tARjX3/I3w3WcfxIN0+0NVJfsVFCM41UeJb+gQE+/2aAoU28Y2uUqr/tLoKekwWqV205TW9VDOwpMGmgCUgZIWyFoB1ij1J0DSlPefNtk+fbioLVVU2jp5Iapw2r0YBQ08RjEYLzQcZnF9nppFExO6ir9eBz23FYjBi0DMl4jPlQkLGZecK7NEUuVT1bISo6+Is/f4qWlQEkM/E5/+W1PjZc8i4DDBYHPm81tS4HDosRo6KSSqSIxpaYDYaYWYhSjnbBpggjzqoaGqpduO1WrEaBmk4Ri4aZmZ1lMhQjtYNnUi79bSuKMBIkEolEstcY6p7kb17poUoAaET63uU/fzhe8vPxEglstidBIpFIJCVGUNNYpzv6pjKRFRVQIikt0kiQSCSScsFcz+nO6od7PLT0NH1jpQ+gI5GsIo0EiUQi2SuEkxPPPsN3Outwb5UB3VjJ8fNnOPHQjaARHuzblwA6Eskq2w7SKZFIJJKtEFTUNPNs92GePhfmwegY98ZnGJsNMR+Jk8goWO1O6uubONbbTrvbtBZAJzbG21cebBq3QCLZa6SRIJFIJCVAMTk42NLFwZauLctqiQCX3v6Yr6UXQbLPSCNBIpFI9gyVZFpFI38Eynzllybv8ualL7kxL88zSPYfeQRSIpFI9hJhotJbR0uDlwPeGmrdTqocNmxmI0ZUUqk4iwsLTE5PcndwiNuTYbaRdF0i2ROkkSCRSCQSiSQv8nSDRCKRSCSSvEgjQSKRSCQSSV6kkSCRSCQSiSQv/x8i/Ja3OdLlpgAAAABJRU5ErkJggg=="
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f91abf56-b017-462a-849f-d03ae0187498",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[domain-name:value = 'google.com' AND domain-name:resolves_to_refs[*].value = '8.8.8.8']",
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
        "type": "note",
        "spec_version": "2.1",
        "id": "note--0d8fdacd-5ed2-42ca-a286-d4880b198827",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "abstract": "EventReport Test",
        "content": "This Event showcases a @[object](f91abf56-b017-462a-849f-d03ae0187498) MISP Object with its @[attribute](7ef43014-e2d6-4a13-b8fd-129fe4009310) value (also reported in a single attribute @[attribute](f9b286a9-3ed6-4ace-a60c-a5fe6529a783)) and the corresponding @[attribute](07a4c4aa-7380-44b5-82d4-06628ee3afba), contextualised with a @[tag](misp-galaxy:mitre-attack-pattern=\"DNS Server - T1584.002\") Galaxy Cluster.\r\n\r\nThe event is also illustrated with the screenshot picturing the case we have here: @![attribute](f715be9f-845f-4d8c-8dce-852b353b3488)\r\n\r\nThe information here is public, as the @[tag](tlp:clear) tag indicates.\r\n",
        "object_refs": [
            "indicator--f9b286a9-3ed6-4ace-a60c-a5fe6529a783",
            "observed-data--f715be9f-845f-4d8c-8dce-852b353b3488",
            "indicator--f91abf56-b017-462a-849f-d03ae0187498"
        ],
        "labels": [
            "misp:data-layer=\"Event Report\""
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--8e8b0fe8-0e9a-416a-911c-2cb6399cdcfa",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "indicates",
        "source_ref": "indicator--f9b286a9-3ed6-4ace-a60c-a5fe6529a783",
        "target_ref": "attack-pattern--c2f59d25-87fe-44aa-8f83-e8e59d077bf5"
    },
    {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {
            "tlp": "white"
        }
    }
]
_FILE_AND_PE_INDICATOR_OBJECT = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--5ac47782-e1b8-40b6-96b4-02510a00020f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND file:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND file:hashes.SHA256 = '3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8' AND file:name = 'oui' AND file:size = '1234' AND file:x_misp_entropy = '1.234' AND file:extensions.'windows-pebinary-ext'.imphash = '23ea835ab4b9017c74dfb023d2301c99' AND file:extensions.'windows-pebinary-ext'.number_of_sections = '8' AND file:extensions.'windows-pebinary-ext'.pe_type = 'exe' AND file:extensions.'windows-pebinary-ext'.optional_header.address_of_entry_point = '5369222868' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2019-03-16T12:31:22Z' AND file:extensions.'windows-pebinary-ext'.x_misp_original_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_internal_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_file_description = 'SSH, Telnet and Rlogin client' AND file:extensions.'windows-pebinary-ext'.x_misp_file_version = 'Release 0.71 (with embedded help)' AND file:extensions.'windows-pebinary-ext'.x_misp_lang_id = '080904B0' AND file:extensions.'windows-pebinary-ext'.x_misp_product_name = 'PuTTy suite' AND file:extensions.'windows-pebinary-ext'.x_misp_product_version = 'Release 0.71' AND file:extensions.'windows-pebinary-ext'.x_misp_company_name = 'Simoe Tatham' AND file:extensions.'windows-pebinary-ext'.x_misp_legal_copyright = 'Copyright © 1997-2019 Simon Tatham.' AND file:extensions.'windows-pebinary-ext'.x_misp_impfuzzy = '192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt' AND file:extensions.'windows-pebinary-ext'.sections[0].entropy = '7.836462238824369' AND file:extensions.'windows-pebinary-ext'.sections[0].name = '.rsrc' AND file:extensions.'windows-pebinary-ext'.sections[0].size = '305152' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.MD5 = '8a2a5fc2ce56b3b04d58539a95390600' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA1 = '0aeb9def096e9f73e9460afe6f8783a32c7eabdf' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA256 = 'c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA512 = '98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SSDEEP = '6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2020-10-25T16:22:00Z",
    "kill_chain_phases": [{"kill_chain_name": "misp-category", "phase_name": "file"}],
    "labels": ['misp:name="file"', 'misp:meta-category="file"', 'misp:to_ids="True"'],
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
        "object_refs": ["file--5ac47782-e1b8-40b6-96b4-02510a00020f"],
        "labels": [
            'misp:name="file"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
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
                "optional_header": {"address_of_entry_point": 5369222868},
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
                "x_misp_legal_copyright": "Copyright © 1997-2019 Simon Tatham.",
                "x_misp_original_filename": "PuTTy",
                "x_misp_product_name": "PuTTy suite",
                "x_misp_product_version": "Release 0.71"
            }
        },
        "x_misp_entropy": "1.234"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac47782-e1b8-40b6-96b4-02510a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[file:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND file:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND file:hashes.SHA256 = '3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8' AND file:name = 'oui' AND file:extensions.'windows-pebinary-ext'.imphash = '23ea835ab4b9017c74dfb023d2301c99' AND file:extensions.'windows-pebinary-ext'.pe_type = 'exe' AND file:extensions.'windows-pebinary-ext'.x_misp_original_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_internal_filename = 'PuTTy' AND file:extensions.'windows-pebinary-ext'.x_misp_impfuzzy = '192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt' AND file:extensions.'windows-pebinary-ext'.sections[0].name = '.rsrc' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.MD5 = '8a2a5fc2ce56b3b04d58539a95390600' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA1 = '0aeb9def096e9f73e9460afe6f8783a32c7eabdf' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA256 = 'c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SHA512 = '98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f' AND file:extensions.'windows-pebinary-ext'.sections[0].hashes.SSDEEP = '6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="file"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--381d4bb0-d07c-4128-8880-eede3c7825f5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac47782-e1b8-40b6-96b4-02510a00020f",
        "target_ref": "observed-data--5ac47782-e1b8-40b6-96b4-02510a00020f"
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
            'misp:name="file"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
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
        "x_misp_attachment": {"value": "non", "data": "Tm9uLW1hbGljaW91cyBmaWxlCg=="}
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
        "hashes": {"MD5": "8764605c6f388c89096b534d33565802"},
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected",
        "x_misp_filename": "oui"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="file"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f9626c9a-ad6f-4351-9553-0a3dbffc46d6",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
        "target_ref": "observed-data--5e384ae7-672c-4250-9cda-3b4da964451a"
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
        "object_refs": ["file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="filename"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "test_file_name"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="github-username"',
            'misp:category="Social network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "user-account",
        "spec_version": "2.1",
        "id": "user-account--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "account_login": "chrisr3d",
        "account_type": "github"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Social network"}
        ],
        "labels": [
            'misp:type="github-username"',
            'misp:category="Social network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["file--34cb1a7c-55ec-412a-8684-ba4a88d83a45"],
        "labels": [
            'misp:type="filename|md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {"MD5": "b2a5abfeef9e36964281a31e17b57c97"},
        "name": "filename1"
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0b488954-0d5a-4ea9-b3e0-23b8839ba94f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "target_ref": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
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
        "object_refs": ["file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"],
        "labels": [
            'misp:type="filename|sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "hashes": {"SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"},
        "name": "filename2"
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--fa05ec41-b6ee-4072-a3be-06970eca319a",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "target_ref": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"
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
        "object_refs": ["file--90bd7dae-b78c-4025-9073-568950c780fb"],
        "labels": [
            'misp:type="filename|sha224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--aea91422-ae58-40c0-815c-e9160fb552a4",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
        "target_ref": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb"
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
        "object_refs": ["file--2007ec09-8137-4a71-a3ce-6ef967bebacf"],
        "labels": [
            'misp:type="filename|sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--40d6c7e0-1e8c-4fe0-8650-f0a959bc878b",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "target_ref": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf"
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
        "object_refs": ["file--c8760340-85a9-4e40-bfde-522d66ef1e9f"],
        "labels": [
            'misp:type="filename|sha384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--61ef6c1d-f504-4d0d-94af-6a745270dce5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "target_ref": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f"
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
        "object_refs": ["file--55ffda25-c3fe-48b5-a6eb-59c986cb593e"],
        "labels": [
            'misp:type="filename|sha512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9dd12c5c-cafb-4087-86ac-98a91cd8eff7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "target_ref": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e"
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
        "object_refs": ["file--9060e814-a36f-45ab-84e5-66fc82dc7cff"],
        "labels": [
            'misp:type="filename|ssdeep"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|ssdeep"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--6170abd7-7ddc-4e22-9cdb-30880b463973",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "target_ref": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff"
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
        "object_refs": ["file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="filename|authentihash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|authentihash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["file--518b4bcb-a86b-4783-9457-391d548b605b"],
        "labels": [
            'misp:type="filename|imphash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {"IMPHASH": "68f013d7437aa653a8a98a05807afeb1"},
        "name": "filename9"
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|imphash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
        "object_refs": ["file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"],
        "labels": [
            'misp:type="filename|pehash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "hashes": {"PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"},
        "name": "filename10"
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|pehash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--a3444188-4046-4544-95ca-11e0da5216ce",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "target_ref": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5"],
        "labels": [
            'misp:type="filename|sha512/224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "hashes": {
            "SHA224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
        },
        "name": "filename11"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512/224 test attribute",
        "pattern": "[file:name = 'filename11' AND file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha512/224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--7ac97cac-bedc-4c6e-b2ee-d72358493da1",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "target_ref": "observed-data--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5"
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
        "object_refs": ["file--2d35a390-ccdd-4d6b-a36d-513b05e3682a"],
        "labels": [
            'misp:type="filename|sha512/256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "hashes": {
            "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
        },
        "name": "filename12"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512/256 test attribute",
        "pattern": "[file:name = 'filename12' AND file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha512/256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--59b95b7e-504d-4fa4-a072-c675498292f5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "target_ref": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a"
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
        "object_refs": ["file--7467406e-88d3-4856-afc9-412459bc3c8b"],
        "labels": [
            'misp:type="filename|tlsh"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7467406e-88d3-4856-afc9-412459bc3c8b",
        "hashes": {
            "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
        },
        "name": "filename13"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|tlsh test attribute",
        "pattern": "[file:name = 'filename13' AND file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|tlsh"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--388e22d6-85b7-4189-8b89-589cdd931ecf",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "target_ref": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b"
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
        "object_refs": ["file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975"],
        "labels": [
            'misp:type="filename|vhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "hashes": {"VHASH": "115056655d15151138z66hz1021z55z66z3"},
        "name": "filename14"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|vhash test attribute",
        "pattern": "[file:name = 'filename14' AND file:hashes.VHASH = '115056655d15151138z66hz1021z55z66z3']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|vhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f7455a6c-4a23-40a2-82f5-a2191822ed59",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "target_ref": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9"],
        "labels": [
            'misp:type="filename|sha3-224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "hashes": {
            "SHA3224": "47d20efbf11c63c0b683560e61f7eb2eb314b68d9e714f8feeba0cfc"
        },
        "name": "filename15"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-224 test attribute",
        "pattern": "[file:name = 'filename15' AND file:hashes.SHA3224 = '47d20efbf11c63c0b683560e61f7eb2eb314b68d9e714f8feeba0cfc']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha3-224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--5415bd6a-5127-4b74-9a26-e0d38952af1c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "target_ref": "observed-data--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9"
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
        "object_refs": ["file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6"],
        "labels": [
            'misp:type="filename|sha3-256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "hashes": {
            "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
        },
        "name": "filename16"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-256 test attribute",
        "pattern": "[file:name = 'filename16' AND file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha3-256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9ecc7f6c-75c7-4663-baea-a4e5d0e30a35",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "target_ref": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--0d40e61c-fafa-4b8c-b5d0-60d768f649a1"],
        "labels": [
            'misp:type="filename|sha3-384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "hashes": {
            "SHA3384": "93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568"
        },
        "name": "filename17"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-384 test attribute",
        "pattern": "[file:name = 'filename17' AND file:hashes.SHA3384 = '93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha3-384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--3b8187c2-a105-452f-88ee-f34bd860782f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "target_ref": "observed-data--0d40e61c-fafa-4b8c-b5d0-60d768f649a1"
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--7e5ec865-a97c-41ba-99ba-a21c006da460"],
        "labels": [
            'misp:type="filename|sha3-512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "hashes": {
            "SHA3-512": "fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748"
        },
        "name": "filename18"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-512 test attribute",
        "pattern": "[file:name = 'filename18' AND file:hashes.SHA3512 = 'fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="filename|sha3-512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f5e0f1d6-2154-45ec-8697-f6231c217133",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "target_ref": "observed-data--7e5ec865-a97c-41ba-99ba-a21c006da460"
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
        "object_refs": ["file--34cb1a7c-55ec-412a-8684-ba4a88d83a45"],
        "labels": [
            'misp:type="md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {"MD5": "b2a5abfeef9e36964281a31e17b57c97"},
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0b488954-0d5a-4ea9-b3e0-23b8839ba94f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "target_ref": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
        "object_refs": ["file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"],
        "labels": [
            'misp:type="sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "hashes": {"SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"},
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--fa05ec41-b6ee-4072-a3be-06970eca319a",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "target_ref": "observed-data--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
        "object_refs": ["file--90bd7dae-b78c-4025-9073-568950c780fb"],
        "labels": [
            'misp:type="sha224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--90bd7dae-b78c-4025-9073-568950c780fb",
        "hashes": {
            "SHA224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--aea91422-ae58-40c0-815c-e9160fb552a4",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
        "target_ref": "observed-data--90bd7dae-b78c-4025-9073-568950c780fb",
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
        "object_refs": ["file--2007ec09-8137-4a71-a3ce-6ef967bebacf"],
        "labels": [
            'misp:type="sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "hashes": {
            "SHA-256": "7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--40d6c7e0-1e8c-4fe0-8650-f0a959bc878b",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "target_ref": "observed-data--2007ec09-8137-4a71-a3ce-6ef967bebacf",
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
        "object_refs": ["file--c8760340-85a9-4e40-bfde-522d66ef1e9f"],
        "labels": [
            'misp:type="sha384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "hashes": {
            "SHA384": "ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--61ef6c1d-f504-4d0d-94af-6a745270dce5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "target_ref": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f",
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
        "object_refs": ["file--55ffda25-c3fe-48b5-a6eb-59c986cb593e"],
        "labels": [
            'misp:type="sha512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "hashes": {
            "SHA-512": "28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9dd12c5c-cafb-4087-86ac-98a91cd8eff7",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "target_ref": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
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
        "object_refs": ["file--9060e814-a36f-45ab-84e5-66fc82dc7cff"],
        "labels": [
            'misp:type="ssdeep"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "hashes": {
            "SSDEEP": "96:QRWkwoBevsL0JsIQ3pq8dxbuTet7eU/uEzAfue9atn0JbIi:QRWktBe80JsIIq8dxKyPew0JbIi"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="ssdeep"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--6170abd7-7ddc-4e22-9cdb-30880b463973",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
        "target_ref": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff",
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
        "object_refs": ["file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="authentihash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {
            "AUTHENTIHASH": "b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="authentihash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
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
        "object_refs": ["file--518b4bcb-a86b-4783-9457-391d548b605b"],
        "labels": [
            'misp:type="imphash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {"IMPHASH": "68f013d7437aa653a8a98a05807afeb1"},
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="imphash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b",
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
        "object_refs": ["file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f"],
        "labels": [
            'misp:type="pehash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "hashes": {"PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"},
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="pehash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--a3444188-4046-4544-95ca-11e0da5216ce",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "target_ref": "observed-data--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5"],
        "labels": [
            'misp:type="sha512/224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "hashes": {
            "SHA224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
        },
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA512/224 test attribute",
        "pattern": "[file:hashes.SHA224 = '5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha512/224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--7ac97cac-bedc-4c6e-b2ee-d72358493da1",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
        "target_ref": "observed-data--bb8c9a01-55ba-4fac-9f2f-cdc31ed774a5",
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
        "object_refs": ["file--2d35a390-ccdd-4d6b-a36d-513b05e3682a"],
        "labels": [
            'misp:type="sha512/256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "hashes": {
            "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha512/256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--59b95b7e-504d-4fa4-a072-c675498292f5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "target_ref": "observed-data--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
        "object_refs": ["file--7467406e-88d3-4856-afc9-412459bc3c8b"],
        "labels": [
            'misp:type="tlsh"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7467406e-88d3-4856-afc9-412459bc3c8b",
        "hashes": {
            "TLSH": "c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="tlsh"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--388e22d6-85b7-4189-8b89-589cdd931ecf",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "target_ref": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b",
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
        "object_refs": ["file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975"],
        "labels": [
            'misp:type="vhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "hashes": {"VHASH": "115056655d15151138z66hz1021z55z66z3"},
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="vhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f7455a6c-4a23-40a2-82f5-a2191822ed59",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "target_ref": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9"],
        "labels": [
            'misp:type="sha3-224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "hashes": {
            "SHA3224": "47d20efbf11c63c0b683560e61f7eb2eb314b68d9e714f8feeba0cfc"
        },
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA3-224 test attribute",
        "pattern": "[file:hashes.SHA3224 = '47d20efbf11c63c0b683560e61f7eb2eb314b68d9e714f8feeba0cfc']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha3-224"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--5415bd6a-5127-4b74-9a26-e0d38952af1c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
        "target_ref": "observed-data--f750c3d9-b7c6-4054-9bb4-f9b0b74688c9",
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
        "object_refs": ["file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6"],
        "labels": [
            'misp:type="sha3-256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "hashes": {
            "SHA3-256": "39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha3-256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9ecc7f6c-75c7-4663-baea-a4e5d0e30a35",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "target_ref": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--0d40e61c-fafa-4b8c-b5d0-60d768f649a1"],
        "labels": [
            'misp:type="sha3-384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "hashes": {
            "SHA3384": "93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568"
        },
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA3-384 test attribute",
        "pattern": "[file:hashes.SHA3384 = '93bc97650d11bd9814f6658989605751f3279da1cffe4c7e3fafc99ce5a7bee9884daa8b70a6f0010132ee9585ead568']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha3-384"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--3b8187c2-a105-452f-88ee-f34bd860782f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
        "target_ref": "observed-data--0d40e61c-fafa-4b8c-b5d0-60d768f649a1",
    },
    {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "object_refs": ["file--7e5ec865-a97c-41ba-99ba-a21c006da460"],
        "labels": [
            'misp:type="sha3-512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "hashes": {
            "SHA3-512": "fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748"
        },
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA3-512 test attribute",
        "pattern": "[file:hashes.SHA3512 = 'fdd67b8bd14e66e4b4fd9b67cff26e8e8d254569e5977c41a1bf11a33ddd758681d8f0a891be4c6c728509e2cbf20ea272a443b2a494fe52e85a3f45954db748']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="sha3-512"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--f5e0f1d6-2154-45ec-8697-f6231c217133",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--7e5ec865-a97c-41ba-99ba-a21c006da460",
        "target_ref": "observed-data--7e5ec865-a97c-41ba-99ba-a21c006da460",
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
        "object_refs": ["file--4846cade-2492-4e7d-856e-2afcd282455b"],
        "labels": [
            'misp:type="telfhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--4846cade-2492-4e7d-856e-2afcd282455b",
        "hashes": {
            "TELFHASH": "b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b"
        },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="telfhash"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"',
        ],
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--65a745c4-8c12-45cd-9127-330f6cd0f812",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--4846cade-2492-4e7d-856e-2afcd282455b",
        "target_ref": "observed-data--4846cade-2492-4e7d-856e-2afcd282455b",
    },
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
        "object_refs": ["domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="hostname"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "circl.lu"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="hostname"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        ],
        "labels": [
            'misp:type="hostname|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
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
        "protocols": ["tcp"]
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="hostname|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    },
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
            "domain-name--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        ],
        "labels": [
            'misp:name="http-request"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--cfdb71ed-889f-4646-a388-43d936e1e3b9",
        "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "dst_ref": "ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7",
        "protocols": ["tcp", "http"],
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
        "resolves_to_refs": ["ipv4-addr--d6f0e3b7-fa5d-4443-aea7-7b60b343bde7"]
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--cfdb71ed-889f-4646-a388-43d936e1e3b9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '8.8.8.8') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '149.13.33.14') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu') AND network-traffic:extensions.'http-request-ext'.request_value = '/projects/internships/' AND network-traffic:extensions.'http-request-ext'.request_value = 'http://circl.lu/projects/internships/']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="http-request"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--3071c6a2-fdb1-453c-b603-e4d6b9017ccc",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--cfdb71ed-889f-4646-a388-43d936e1e3b9",
        "target_ref": "observed-data--cfdb71ed-889f-4646-a388-43d936e1e3b9"
    }
]
_IDENTITY_OBJECT = {
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
            'misp:name="image"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="image"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--d90dbb2f-9511-43c1-86e4-80d4cf7c5b57",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--939b2f03-c487-4f62-a90e-cab7acfee294",
        "target_ref": "observed-data--939b2f03-c487-4f62-a90e-cab7acfee294"
    }
]
_INTRUSION_SET_GALAXY = {
    "type": "intrusion-set",
    "spec_version": "2.1",
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
_INTRUSION_SET_OBJECT = {
    "type": "intrusion-set",
    "spec_version": "2.1",
    "id": "intrusion-set--79a012ce-9eac-4249-9e7c-fadddfb6e93d",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Bobcat Breakin",
    "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first.",
    "aliases": [
        "Zookeeper"
    ],
    "first_seen": "2016-04-06T20:03:48Z",
    "last_seen": "2017-05-15T21:05:06Z",
    "goals": [
        "acquisition-theft",
        "harassment",
        "damage"
    ],
    "resource_level": "organization",
    "primary_motivation": "organizational gain",
    "secondary_motivations": [
        "personal gain"
    ],
    "labels": [
        "misp:name=\"intrusion-set\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
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
            'misp:type="ip-src"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "protocols": ["tcp"]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "1.2.3.4"
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="ip-src"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            'misp:type="ip-dst"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "protocols": ["tcp"]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "5.6.7.8"
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="ip-dst"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
            'misp:type="ip-src|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "src_port": 1234,
        "protocols": ["tcp"]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "1.2.3.4"
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="ip-src|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
            'misp:type="ip-dst|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_ref": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "dst_port": 5678,
        "protocols": ["tcp"]
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "5.6.7.8"
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="ip-dst|port"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
            'misp:name="ip-port"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": "network-traffic--5ac47edc-31e4-4402-a7b6-040d0a00020f",
        "start": "2020-10-25T16:22:00Z",
        "dst_ref": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "dst_port": 443,
        "protocols": ["ipv4"],
        "x_misp_domain": "circl.lu"
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "149.13.33.14"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[(network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '149.13.33.14') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu')]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="ip-port"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--37dd31ee-24a7-4a7c-9704-aecef00e7082",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
        "target_ref": "observed-data--5ac47edc-31e4-4402-a7b6-040d0a00020f"
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
            'misp:name="lnk"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
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
        "hashes": {"MD5": "8764605c6f388c89096b534d33565802"},
        "encryption_algorithm": "mime-type-indicated",
        "decryption_key": "infected",
        "x_misp_filename": "oui"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="lnk"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--07f16a3d-81c4-5672-bfee-35849cabd11d",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--153ef8d5-9182-45ec-bf1c-5819932b9ab7",
        "target_ref": "observed-data--153ef8d5-9182-45ec-bf1c-5819932b9ab7"
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
        "description": "Sweden",
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
        "description": "Nothern Europe",
        "region": "northern-europe",
        "labels": [
            "misp:galaxy-name=\"Regions UN M49\"",
            "misp:galaxy-type=\"region\""
        ],
        "x_misp_subregion": [
            "830 - Channel Islands",
            "248 - Åland Islands",
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
        "object_refs": ["mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="mac-address"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": "mac-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "12:34:56:78:90:ab"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[mac-addr:value = '12:34:56:78:90:ab']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="mac-address"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
    }
]
_MALWARE_GALAXY = {
    "type": "malware",
    "spec_version": "2.1",
    "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "BISCUIT",
    "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
    "is_family": False,
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
            'misp:type="malware-sample"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {"MD5": "8764605c6f388c89096b534d33565802"},
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
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="malware-sample"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="mutex"',
            'misp:category="Artifacts dropped"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "name": "MutexTest"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Artifacts dropped"}
        ],
        "labels": [
            'misp:type="mutex"',
            'misp:category="Artifacts dropped"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["mutex--b0f55591-6a63-4fbd-a169-064e64738d95"],
        "labels": [
            'misp:name="mutex"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "mutex",
        "spec_version": "2.1",
        "id": "mutex--b0f55591-6a63-4fbd-a169-064e64738d95",
        "name": "MutexTest",
        "x_misp_description": "Test mutex on unix",
        "x_misp_operating_system": "Unix"
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--b0f55591-6a63-4fbd-a169-064e64738d95",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[mutex:name = 'MutexTest']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="mutex"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--20389086-0cc2-45d4-b7a9-f4d367e49dc5",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--b0f55591-6a63-4fbd-a169-064e64738d95",
        "target_ref": "observed-data--b0f55591-6a63-4fbd-a169-064e64738d95"
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
            'misp:name="netflow"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
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
        "protocols": ["tcp", "ip"],
        "extensions": {"tcp-ext": {"src_flags_hex": "00000002"}}
    },
    {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": "ipv4-addr--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "1.2.3.4",
        "belongs_to_refs": ["autonomous-system--53a12da9-4b66-4809-b0b4-e9de3172e7a0"]
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
        "belongs_to_refs": ["autonomous-system--f2259650-bc33-4b64-a3a8-a324aa7ea6bb"]
    },
    {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": "autonomous-system--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "number": 5678
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8')]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="netflow"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--b0d20387-14e3-40ae-a170-58db0dd99bc6",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--419eb5a9-d232-4aa1-864e-2f4d7270a8f9",
        "target_ref": "observed-data--419eb5a9-d232-4aa1-864e-2f4d7270a8f9"
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
            'misp:name="network-connection"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
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
        "protocols": ["ip", "tcp", "http"],
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5afacc53-c0b0-4825-a6ee-03c80a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu')]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="network-connection"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--7a706d93-4c0b-4084-bbee-552515ffac59",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5afacc53-c0b0-4825-a6ee-03c80a00020f",
        "target_ref": "observed-data--5afacc53-c0b0-4825-a6ee-03c80a00020f"
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
            'misp:name="network-socket"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
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
        "protocols": ["tcp"],
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4') AND (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '5.6.7.8') AND (network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'circl.lu')]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="network-socket"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--bc5e3b34-b274-4ef7-b082-ee286c87ce84",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5afb3223-0988-4ef1-a920-02070a00020f",
        "target_ref": "observed-data--5afb3223-0988-4ef1-a920-02070a00020f"
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
_PERSON_OBJECT = {
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
            'misp:name="process"',
            'misp:meta-category="misc"',
            'misp:to_ids="False"'
        ]
    },
    {
        "type": "process",
        "spec_version": "2.1",
        "id": "process--5e39776a-b284-40b3-8079-22fea964451a",
        "is_hidden": True,
        "pid": 2510,
        "image_ref": "file--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "parent_ref": "process--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "child_refs": ["process--518b4bcb-a86b-4783-9457-391d548b605b"],
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5e39776a-b284-40b3-8079-22fea964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[process:pid = '2510' AND process:image_ref.name = 'test_process.exe' AND process:parent_ref.image_ref.name = 'parent_process.exe']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "misc"}
        ],
        "labels": [
            'misp:name="process"',
            'misp:meta-category="misc"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--74004798-7758-4553-90fe-60cbb722dc62",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5e39776a-b284-40b3-8079-22fea964451a",
        "target_ref": "observed-data--5e39776a-b284-40b3-8079-22fea964451a"
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
        "object_refs": ["windows-registry-key--5ac3379c-3e74-44ba-9160-04120a00020f"],
        "labels": [
            'misp:name="registry-key"',
            'misp:meta-category="file"',
            'misp:to_ids="False"'
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac3379c-3e74-44ba-9160-04120a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[windows-registry-key:key = 'hkey_local_machine\\\\system\\\\bar\\\\foo']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "file"}
        ],
        "labels": [
            'misp:name="registry-key"',
            'misp:meta-category="file"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0ec23b58-fbd1-4dbb-be28-6a48d4677410",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac3379c-3e74-44ba-9160-04120a00020f",
        "target_ref": "observed-data--5ac3379c-3e74-44ba-9160-04120a00020f"
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
        "object_refs": ["windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="regkey"',
            'misp:category="Persistence mechanism"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "key": "HKLM\\Software\\mthjk"
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Persistence mechanism"}
        ],
        "labels": [
            'misp:type="regkey"',
            'misp:category="Persistence mechanism"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="regkey|value"',
            'misp:category="Persistence mechanism"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": "windows-registry-key--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "key": "HKLM\\Software\\mthjk",
        "values": [{"data": "%DATA%\\1234567890"}]
    },
    {
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
            {"kill_chain_name": "misp-category", "phase_name": "Persistence mechanism"}
        ],
        "labels": [
            'misp:type="regkey|value"',
            'misp:category="Persistence mechanism"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
_TOOL_GALAXY = {
    "type": "tool",
    "spec_version": "2.1",
    "id": "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "cmd",
    "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
    "aliases": [
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
        "object_refs": ["url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="link"',
            'misp:category="External analysis"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "value": "https://misp-project.org/download/"
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "External analysis"}
        ],
        "labels": [
            'misp:type="link"',
            'misp:category="External analysis"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["url--518b4bcb-a86b-4783-9457-391d548b605b"],
        "labels": [
            'misp:type="uri"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--518b4bcb-a86b-4783-9457-391d548b605b",
        "value": "https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova"
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="uri"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
        "object_refs": ["url--34cb1a7c-55ec-412a-8684-ba4a88d83a45"],
        "labels": [
            'misp:type="url"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "value": "https://vm.misp-project.org/latest/"
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
            {"kill_chain_name": "misp-category", "phase_name": "Network activity"}
        ],
        "labels": [
            'misp:type="url"',
            'misp:category="Network activity"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0b488954-0d5a-4ea9-b3e0-23b8839ba94f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "target_ref": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
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
        "object_refs": ["url--5ac347ca-dac4-4562-9775-04120a00020f"],
        "labels": [
            'misp:name="url"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac347ca-dac4-4562-9775-04120a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[url:value = 'https://www.circl.lu/team' AND url:x_misp_domain = 'circl.lu' AND url:x_misp_host = 'www.circl.lu' AND url:x_misp_ip = '149.13.33.14']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="url"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9c435f8e-5d9c-4f84-9650-6bb3355ae28a",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac347ca-dac4-4562-9775-04120a00020f",
        "target_ref": "observed-data--5ac347ca-dac4-4562-9775-04120a00020f"
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
        "object_refs": ["x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"],
        "labels": [
            'misp:type="x509-fingerprint-md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "hashes": {"MD5": "8764605c6f388c89096b534d33565802"}
    },
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="x509-fingerprint-md5"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--600e528a-1967-4489-a604-a04af707490c",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "target_ref": "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
        "object_refs": ["x509-certificate--518b4bcb-a86b-4783-9457-391d548b605b"],
        "labels": [
            'misp:type="x509-fingerprint-sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--518b4bcb-a86b-4783-9457-391d548b605b",
        "hashes": {"SHA-1": "46aba99aa7158e4609aaa72b50990842fd22ae86"}
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="x509-fingerprint-sha1"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--328c53d5-6441-4ee1-8546-83a089dc9291",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "target_ref": "observed-data--518b4bcb-a86b-4783-9457-391d548b605b"
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
        "object_refs": ["x509-certificate--34cb1a7c-55ec-412a-8684-ba4a88d83a45"],
        "labels": [
            'misp:type="x509-fingerprint-sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": "x509-certificate--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "hashes": {
            "SHA-256": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
        }
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
            {"kill_chain_name": "misp-category", "phase_name": "Payload delivery"}
        ],
        "labels": [
            'misp:type="x509-fingerprint-sha256"',
            'misp:category="Payload delivery"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--0b488954-0d5a-4ea9-b3e0-23b8839ba94f",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "target_ref": "observed-data--34cb1a7c-55ec-412a-8684-ba4a88d83a45"
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
        "object_refs": ["x509-certificate--5ac3444e-145c-4749-8467-02550a00020f"],
        "labels": [
            'misp:name="x509"',
            'misp:meta-category="network"',
            'misp:to_ids="False"'
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
    },
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5ac3444e-145c-4749-8467-02550a00020f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[x509-certificate:hashes.MD5 = 'b2a5abfeef9e36964281a31e17b57c97' AND x509-certificate:hashes.SHA1 = '5898fc860300e228dcd54c0b1045b5fa0dcda502' AND x509-certificate:issuer = 'Issuer Name']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2020-10-25T16:22:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "misp-category", "phase_name": "network"}
        ],
        "labels": [
            'misp:name="x509"',
            'misp:meta-category="network"',
            'misp:to_ids="True"'
        ]
    },
    {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--ef692888-dc5d-4f5c-85c2-b9a13f2ea85e",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "relationship_type": "based-on",
        "source_ref": "indicator--5ac3444e-145c-4749-8467-02550a00020f",
        "target_ref": "observed-data--5ac3444e-145c-4749-8467-02550a00020f"
    }
]


class TestInternalSTIX21Bundles(TestSTIX2Bundles):
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
        grouping = deepcopy(cls.__grouping)
        grouping.update(
            cls._populate_references(
                *(stix_object['id'] for stix_object in stix_objects)
            )
        )
        bundle['objects'] = [deepcopy(cls.__identity), grouping, *stix_objects]
        return dict_to_stix2(bundle, allow_custom=True)

    ############################################################################
    #                            ATTRIBUTES SAMPLES                            #
    ############################################################################

    @classmethod
    def get_bundle_with_AS_indicator_attribute(cls):
        return cls.__assemble_bundle(*_AS_INDICATOR_ATTRIBUTE)

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
            data = b64encode(f.read()).decode()
        *_, artifact, indicator, _ = observables
        artifact['payload_bin'] = data
        pattern = [
            f"file:content_ref.payload_bin = '{data}'",
            "file:name = 'oui' AND file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
            "file:content_ref.mime_type = 'application/zip'",
            "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
            "file:content_ref.decryption_key = 'infected'"
        ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
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

    ############################################################################
    #                              EVENTS SAMPLES                              #
    ############################################################################

    @classmethod
    def get_bundle_with_analyst_data(cls):
        return cls.__assemble_bundle(*_ANALYST_DATA_SAMPLES)

    @classmethod
    def get_bundle_with_custom_labels(cls):
        indicator = deepcopy(_DOMAIN_IP_INDICATOR_OBJECT)
        indicator['labels'].append('Object tag')
        observed_data, domain, ip = deepcopy(_DOMAIN_IP_OBSERVABLE_ATTRIBUTE)
        observed_data['labels'].append('Attribute tag')
        return cls.__assemble_bundle(indicator, observed_data, domain, ip)

    @classmethod
    def get_bundle_with_event_report(cls):
        return cls.__assemble_bundle(*_EVENT_REPORT)

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

    ############################################################################
    #                             GALAXIES SAMPLES                             #
    ############################################################################

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

    ############################################################################
    #                           MISP OBJECTS SAMPLES                           #
    ############################################################################

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
        for observable, feature in zip(observables[1::4], features):
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
        return cls.__assemble_bundle(*_ASN_INDICATOR_OBJECT)

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
        *_, artifact, indicator, _ = observables
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            data = b64encode(f.read()).decode()
        artifact['payload_bin'] = data
        pattern = [
            "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
            "file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86'",
            "file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b'",
            "file:name = 'oui'",
            f"(file:content_ref.payload_bin = '{data}'",
            "file:content_ref.x_misp_filename = 'oui'",
            "file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802'",
            "file:content_ref.mime_type = 'application/zip'",
            "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
            "file:content_ref.decryption_key = 'infected')"
        ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
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
    def get_bundle_with_identity_object(cls):
        return cls.__assemble_bundle(_IDENTITY_OBJECT)

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
            data = b64encode(f.read()).decode()
        *_, artifact, indicator, _ = observables
        artifact['payload_bin'] = data
        pattern = [
            "file:name = 'STIX.png'",
            f"file:content_ref.payload_bin = '{data}'",
            "file:content_ref.mime_type = 'image/png'",
            "file:content_ref.x_misp_filename = 'STIX.png'",
            "file:content_ref.url = 'https://oasis-open.github.io/cti-documentation/img/STIX.png'"
        ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_intrusion_set_object(cls):
        return cls.__assemble_bundle(_INTRUSION_SET_OBJECT)

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
            data = b64encode(f.read()).decode()
        *_, artifact, indicator, _ = observables
        artifact['payload_bin'] = data
        pattern = [
            "file:name = 'oui'",
            "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
            "file:hashes.SHA1 = '46aba99aa7158e4609aaa72b50990842fd22ae86'",
            "file:hashes.SHA256 = 'ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b'",
            f"(file:content_ref.payload_bin = '{data}'",
            "file:content_ref.x_misp_filename = 'oui'",
            "file:content_ref.hashes.MD5 = '8764605c6f388c89096b534d33565802'",
            "file:content_ref.mime_type = 'application/zip'",
            "file:content_ref.encryption_algorithm = 'mime-type-indicated'",
            "file:content_ref.decryption_key = 'infected')"
        ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
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
    def get_bundle_with_person_object(cls):
        return cls.__assemble_bundle(_PERSON_OBJECT)

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
