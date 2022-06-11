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
        "id": "indicator--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'gitlab' AND user-account:user_id = '1234567890' AND user-account:display_name = 'John Doe' AND user-account:account_login = 'j0hnd0e']",
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
        "id": "indicator--7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "pattern": "[user-account:account_type = 'telegram' AND user-account:user_id = '1234567890' AND user-account:account_login = 'T3l3gr4mUs3r' AND user-account:x_misp_phone = '0112233445' AND user-account:x_misp_phone = '0556677889']",
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
        "id": "observed-data--20a39ad0-e8e1-4917-9fb8-40fecc4d0e7b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1234567890",
                "account_login": "j0hnd0e",
                "account_type": "gitlab",
                "display_name": "John Doe"
            }
        },
        "labels": [
            "misp:name=\"gitlab-user\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--7ecc4537-89cd-4f17-8027-6e0f70710c53",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1234567890",
                "account_login": "T3l3gr4mUs3r",
                "account_type": "telegram",
                "x_misp_phone": [
                    "0112233445",
                    "0556677889"
                ]
            }
        },
        "labels": [
            "misp:name=\"telegram-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    }
]
_ACCOUNT_WITH_ATTACHMENT_INDICATOR_OBJECTS = [
    {
        "type": "indicator",
        "id": "indicator--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "indicator--5177abbd-c437-4acb-9173-eee371ad24da",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "indicator--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "indicator--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "indicator--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "indicator--5d234f25-539c-4d12-bf93-2c46a964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
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
        "id": "observed-data--7d8ac653-b65c-42a6-8420-ddc71d65f50d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1392781243",
                "account_login": "octocat",
                "account_type": "facebook",
                "x_misp_link": "https://facebook.com/octocat",
                "x_misp_user_avatar": {
                    "value": "octocat.png",
                }
            }
        },
        "labels": [
            "misp:name=\"facebook-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--5177abbd-c437-4acb-9173-eee371ad24da",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1",
                "account_login": "octocat",
                "account_type": "github",
                "display_name": "Octo Cat",
                "x_misp_organisation": "GitHub",
                "x_misp_profile_image": {
                    "value": "octocat.png"
                }
            }
        },
        "labels": [
            "misp:name=\"github-user\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--7b0698a0-209a-4da0-a5c5-cfc4734f3af2",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "42",
                "account_login": "ParlerOctocat",
                "account_type": "parler",
                "x_misp_human": False,
                "x_misp_profile_photo": {
                    "value": "octocat.png"
                }
            }
        },
        "labels": [
            "misp:name=\"parler-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--43d3eff0-fabc-4663-9493-fad3a1eed0d5",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "666",
                "account_login": "RedditOctocat",
                "account_type": "reddit",
                "x_misp_account_avatar": {
                    "value": "octocat.png"
                },
                "x_misp_description": "Reddit account of the OctoCat"
            }
        },
        "labels": [
            "misp:name=\"reddit-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--6baef273-d2c3-4ef1-8a93-d2cf552e7bfb",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "user_id": "1357111317",
                "account_login": "octocat",
                "account_type": "twitter",
                "display_name": "Octo Cat",
                "x_misp_followers": "666",
                "x_misp_profile_image": {
                    "value": "octocat.png",
                }
            }
        },
        "labels": [
            "misp:name=\"twitter-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--5d234f25-539c-4d12-bf93-2c46a964451a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
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
                "x_misp_password": "P4ssw0rd1234!",
                "x_misp_user_avatar": {
                    "value": "octocat.png",
                }
            }
        },
        "labels": [
            "misp:name=\"user-account\"",
            "misp:meta-category=\"misc\"",
            "misp:to_ids=\"False\""
        ]
    }
]
_AS_INDICATOR_ATTRIBUTE = {
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
_AS_OBSERVABLE_ATTRIBUTE = {
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
_ASN_INDICATOR_OBJECT = {
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
        "misp:name=\"asn\"",
        "misp:meta-category=\"network\"",
        "misp:to_ids=\"True\""
    ]
}
_ASN_OBSERVABLE_OBJECT = {
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
        "misp:name=\"asn\"",
        "misp:meta-category=\"network\"",
        "misp:to_ids=\"False\""
    ]
}
_ATTACHMENT_INDICATOR_ATTRIBUTE = {
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
_ATTACHMENT_OBSERVABLE_ATTRIBUTE = {
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
_ATTACK_PATTERN_OBJECT = {
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
    "id": "indicator--3f53a829-6307-4006-b7a2-ff53dace4159",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[software:cpe = 'cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*' AND software:languages = 'ENG' AND software:name = 'Word' AND software:vendor = 'Microsoft' AND software:version = '2002' AND software:x_misp_description = 'Microsoft Word is a word processing software developed by Microsoft.']",
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
_CPE_ASSET_OBSERVABLE_OBJECT = {
    "type": "observed-data",
    "id": "observed-data--3f53a829-6307-4006-b7a2-ff53dace4159",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "first_observed": "2020-10-25T16:22:00Z",
    "last_observed": "2020-10-25T16:22:00Z",
    "number_observed": 1,
    "objects": {
        "0": {
            "type": "software",
            "name": "Word",
            "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "languages": [
                "ENG"
            ],
            "vendor": "Microsoft",
            "version": "2002",
            "x_misp_description": "Microsoft Word is a word processing software developed by Microsoft."
        }
    },
    "labels": [
        "misp:name=\"cpe-asset\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
    ]
}
_CREDENTIAL_INDICATOR_OBJECT = {
    "type": "indicator",
    "id": "indicator--5b1f9378-46d4-494b-a4c1-044e0a00020f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[user-account:user_id = 'misp' AND user-account:x_misp_text = 'MISP default credentials' AND user-account:x_misp_password = 'Password1234' AND user-account:x_misp_type = 'password' AND user-account:x_misp_origin = 'malware-analysis' AND user-account:x_misp_format = 'clear-text' AND user-account:x_misp_notification = 'victim-notified']",
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
_CREDENTIAL_OBSERVABLE_OBJECT = {
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
            "x_misp_format": "clear-text",
            "x_misp_notification": "victim-notified",
            "x_misp_origin": "malware-analysis",
            "x_misp_password": "Password1234",
            "x_misp_text": "MISP default credentials",
            "x_misp_type": "password"
        }
    },
    "labels": [
        "misp:name=\"credential\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
    ]
}
_DOMAIN_INDICATOR_ATTRIBUTE = {
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
_DOMAIN_OBSERVABLE_ATTRIBUTE = {
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
_DOMAIN_IP_INDICATOR_ATTRIBUTE = {
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
_DOMAIN_IP_INDICATOR_OBJECT = {
    "type": "indicator",
    "id": "indicator--dc624447-684a-488f-9e16-f78f717d8efd",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[domain-name:value = 'circl.lu' AND domain-name:x_misp_hostname = 'circl.lu' AND domain-name:resolves_to_refs[*].value = '149.13.33.14' AND domain-name:x_misp_port = '8443']",
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
_DOMAIN_IP_OBSERVABLE_ATTRIBUTE ={
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
_DOMAIN_IP_OBSERVABLE_OBJECTS = [
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
                "type": "ipv4-addr",
                "value": "149.13.33.14"
            },
            "1": {
                "type": "ipv4-addr",
                "value": "185.194.93.14"
            },
            "2": {
                "type": "domain-name",
                "value": "misp-project.org",
                "resolves_to_refs": [
                    "0",
                    "1"
                ]
            },
            "3": {
                "type": "domain-name",
                "value": "circl.lu",
                "resolves_to_refs": [
                    "0",
                    "1"
                ]
            }
        },
        "labels": [
            "misp:name=\"domain-ip\"",
            "misp:meta-category=\"network\"",
            "misp:to_ids=\"False\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--dc624447-684a-488f-9e16-f78f717d8efd",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "first_observed": "2020-10-25T16:22:00Z",
        "last_observed": "2020-10-25T16:22:00Z",
        "number_observed": 1,
        "objects": {
            "1": {
                "type": "ipv4-addr",
                "value": "149.13.33.14"
            },
            "0": {
                "type": "domain-name",
                "value": "circl.lu",
                "resolves_to_refs": [
                    "1"
                ],
                "x_misp_hostname": "circl.lu",
                "x_misp_port": "8443"
            }
        },
        "labels": [
            "misp:name=\"domain-ip\"",
            "misp:meta-category=\"network\"",
            "misp:to_ids=\"False\""
        ]
    }
]
_EMAIL_ATTACHMENT_INDICATOR_ATTRIBUTE = {
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
_EMAIL_ATTACHMENT_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": True,
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
_EMAIL_BODY_INDICATOR_ATTRIBUTE = {
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
_EMAIL_BODY_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
            "body": "Email body test"
        }
    },
    "labels": [
        "misp:type=\"email-body\"",
        "misp:category=\"Payload delivery\""
    ]
}
_EMAIL_DESTINATION_INDICATOR_ATTRIBUTE = {
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
_EMAIL_DESTINATION_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
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
_EMAIL_HEADER_INDICATOR_ATTRIBUTE = {
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
_EMAIL_HEADER_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
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
_EMAIL_INDICATOR_ATTRIBUTE = {
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
_EMAIL_INDICATOR_OBJECT = {
    "type": "indicator",
    "id": "indicator--5e396622-2a54-4c8d-b61d-159da964451a",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "pattern": "[email-message:to_refs[0].value = 'jdoe@random.org' AND email-message:to_refs[0].display_name = 'John Doe' AND email-message:cc_refs[0].value = 'diana.prince@dc.us' AND email-message:cc_refs[0].display_name = 'Diana Prince' AND email-message:cc_refs[1].value = 'marie.curie@nobel.fr' AND email-message:cc_refs[1].display_name = 'Marie Curie' AND email-message:bcc_refs[0].value = 'jfk@gov.us' AND email-message:bcc_refs[0].display_name = 'John Fitzgerald Kennedy' AND email-message:from_ref.value = 'donald.duck@disney.com' AND email-message:from_ref.display_name = 'Donald Duck' AND email-message:additional_header_fields.reply_to = 'reply-to@email.test' AND email-message:subject = 'Email test subject' AND email-message:additional_header_fields.x_mailer = 'x-mailer-test' AND email-message:body_multipart[0].body_raw_ref.name = 'attachment1.file' AND email-message:body_multipart[0].content_disposition = 'attachment' AND email-message:body_multipart[1].body_raw_ref.name = 'attachment2.file' AND email-message:body_multipart[1].content_disposition = 'attachment' AND email-message:x_misp_user_agent = 'Test user agent' AND email-message:x_misp_mime_boundary = 'Test mime boundary' AND email-message:x_misp_message_id = '25']",
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
_EMAIL_OBSERVABLE_ATTRIBUTE = {
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
_EMAIL_OBSERVABLE_OBJECT = {
    "type": "observed-data",
    "id": "observed-data--5e396622-2a54-4c8d-b61d-159da964451a",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "first_observed": "2020-10-25T16:22:00Z",
    "last_observed": "2020-10-25T16:22:00Z",
    "number_observed": 1,
    "objects": {
        "0": {
            "type": "email-message",
            "is_multipart": True,
            "from_ref": "1",
            "to_refs": [
                "2"
            ],
            "cc_refs": [
                "3",
                "4"
            ],
            "bcc_refs": [
                "5"
            ],
            "subject": "Email test subject",
            "additional_header_fields": {
                "Reply-To": "reply-to@email.test",
                "X-Mailer": "x-mailer-test"
            },
            "body_multipart": [
                {
                    "body_raw_ref": "6",
                    "content_disposition": "attachment; filename='attachment1.file'"
                },
                {
                    "body_raw_ref": "7",
                    "content_disposition": "attachment; filename='attachment2.file'"
                }
            ],
            "x_misp_message_id": "25",
            "x_misp_mime_boundary": "Test mime boundary",
            "x_misp_user_agent": "Test user agent"
        },
        "1": {
            "type": "email-addr",
            "value": "donald.duck@disney.com",
            "display_name": "Donald Duck"
        },
        "2": {
            "type": "email-addr",
            "value": "jdoe@random.org",
            "display_name": "John Doe"
        },
        "3": {
            "type": "email-addr",
            "value": "diana.prince@dc.us",
            "display_name": "Diana Prince"
        },
        "4": {
            "type": "email-addr",
            "value": "marie.curie@nobel.fr",
            "display_name": "Marie Curie"
        },
        "5": {
            "type": "email-addr",
            "value": "jfk@gov.us",
            "display_name": "John Fitzgerald Kennedy"
        },
        "6": {
            "type": "file",
            "name": "attachment1.file"
        },
        "7": {
            "type": "file",
            "name": "attachment2.file"
        }
    },
    "labels": [
        "misp:name=\"email\"",
        "misp:meta-category=\"network\"",
        "misp:to_ids=\"False\""
    ]
}
_EMAIL_REPLY_TO_INDICATOR_ATTRIBUTE = {
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
_EMAIL_REPLY_TO_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
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
_EMAIL_SOURCE_INDICATOR_ATTRIBUTE = {
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
_EMAIL_SOURCE_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
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
_EMAIL_SUBJECT_INDICATOR_ATTRIBUTE = {
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
_EMAIL_SUBJECT_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
            "subject": "Test Subject"
        }
    },
    "labels": [
        "misp:type=\"email-subject\"",
        "misp:category=\"Payload delivery\""
    ]
}
_EMAIL_X_MAILER_INDICATOR_ATTRIBUTE = {
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
_EMAIL_X_MAILER_OBSERVABLE_ATTRIBUTE = {
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
            "is_multipart": False,
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
_EMPLOYEE_OBJECT = {
    "type": "identity",
    "id": "identity--685a38e1-3ca1-40ef-874d-3a04b9fb3af6",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "John Doe",
    "description": "John Doe is known",
    "identity_class": "individual",
    "contact_information": "email-address: jdoe@email.com",
    "labels": [
        "misp:name=\"employee\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
    ],
    "x_misp_employee_type": "Supervisor"
}
_FILE_AND_PE_INDICATOR_OBJECT = {
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
        "misp:name=\"file\"",
        "misp:meta-category=\"file\"",
        "misp:to_ids=\"True\""
    ]
}
_FILE_AND_PE_OBSERVABLE_OBJECT = {
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
        "misp:name=\"file\"",
        "misp:meta-category=\"file\"",
        "misp:to_ids=\"False\""
    ]
}
_FILE_INDICATOR_OBJECT = {
    "type": "indicator",
    "id": "indicator--5e384ae7-672c-4250-9cda-3b4da964451a",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
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
_FILE_OBSERVABLE_OBJECT = {
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
            "content_ref": "2",
            "x_misp_attachment": {
                "value": "non",
                "data": "Tm9uLW1hbGljaW91cyBmaWxlCg=="
            }
        },
        "1": {
            "type": "directory",
            "path": "/var/www/MISP/app/files/scripts/tmp"
        },
        "2": {
            "type": "artifact",
            "mime_type": "application/zip",
            "hashes": {
                "MD5": "8764605c6f388c89096b534d33565802"
            },
            "x_misp_filename": "oui"
        }
    },
    "labels": [
        "misp:name=\"file\"",
        "misp:meta-category=\"file\"",
        "misp:to_ids=\"False\""
    ]
}
_FILENAME_INDICATOR_ATTRIBUTE = {
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
_FILENAME_OBSERVABLE_ATTRIBUTE = {
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
_GITHUB_USERNAME_INDICATOR_ATTRIBUTE = {
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
_HASH_COMPOSITE_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
    },
    {
        "type": "indicator",
        "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
    },
    {
        "type": "indicator",
        "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
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
    },
    {
        "type": "indicator",
        "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha256 test attribute",
        "pattern": "[file:name = 'filename4' AND file:hashes.SHA256 = '7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4']",
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
        "id": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha384 test attribute",
        "pattern": "[file:name = 'filename5' AND file:hashes.SHA384 = 'ec1f92f1d30b71ffd866fe643a5fde9b64ac86398bfd3f24302bb2bae97e2b281f67666e7167dfdeb60006e2924636ce']",
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
        "id": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512 test attribute",
        "pattern": "[file:name = 'filename6' AND file:hashes.SHA512 = '28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe']",
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
        "id": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
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
    },
    {
        "type": "indicator",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|authentihash test attribute",
        "pattern": "[file:name = 'filename8' AND file:hashes.AUTHENTIHASH = 'b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc']",
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
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|imphash test attribute",
        "pattern": "[file:name = 'filename9' AND file:hashes.IMPHASH = '68f013d7437aa653a8a98a05807afeb1']",
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
        "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|pehash test attribute",
        "pattern": "[file:name = 'filename10' AND file:hashes.PEHASH = 'ffb7a38174aab4744cc4a509e34800aee9be8e57']",
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
        "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha512/256 test attribute",
        "pattern": "[file:name = 'filename11' AND file:hashes.SHA256 = '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93']",
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
        "id": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|sha3-256 test attribute",
        "pattern": "[file:name = 'filename12' AND file:hashes.SHA3256 = '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4']",
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
    },
    {
        "type": "indicator",
        "id": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|tlsh test attribute",
        "pattern": "[file:name = 'filename14' AND file:hashes.TLSH = 'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396813829297']",
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
        "id": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Filename|vhash test attribute",
        "pattern": "[file:name = 'filename15' AND file:hashes.VHASH = '115056655d15151138z66hz1021z55z66z3']",
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
    }
]
_HASH_COMPOSITE_OBSERVABLE_ATTRIBUTES = [
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
                    "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                },
                "name": "filename1"
            }
        },
        "labels": [
            "misp:type=\"filename|md5\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                },
                "name": "filename2"
            }
        },
        "labels": [
            "misp:type=\"filename|sha1\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                },
                "name": "filename3"
            }
        },
        "labels": [
            "misp:type=\"filename|sha224\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-256": "7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4"
                },
                "name": "filename4"
            }
        },
        "labels": [
            "misp:type=\"filename|sha256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f",
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
                "name": "filename5"
            }
        },
        "labels": [
            "misp:type=\"filename|sha384\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
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
                    "SHA-512": "28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe"
                },
                "name": "filename6"
            }
        },
        "labels": [
            "misp:type=\"filename|sha512\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff",
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
    },
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
                    "AUTHENTIHASH": "b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc"
                },
                "name": "filename8"
            }
        },
        "labels": [
            "misp:type=\"filename|authentihash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "IMPHASH": "68f013d7437aa653a8a98a05807afeb1"
                },
                "name": "filename9"
            }
        },
        "labels": [
            "misp:type=\"filename|imphash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"
                },
                "name": "filename10"
            }
        },
        "labels": [
            "misp:type=\"filename|pehash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                },
                "name": "filename11"
            }
        },
        "labels": [
            "misp:type=\"filename|sha512/256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
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
                "name": "filename12"
            }
        },
        "labels": [
            "misp:type=\"filename|sha3-256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b",
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
                "name": "filename14"
            }
        },
        "labels": [
            "misp:type=\"filename|tlsh\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
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
                    "VHASH": "115056655d15151138z66hz1021z55z66z3"
                },
                "name": "filename15"
            }
        },
        "labels": [
            "misp:type=\"filename|vhash\"",
            "misp:category=\"Payload delivery\""
        ]
    }
]
_HASH_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
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
    },
    {
        "type": "indicator",
        "id": "indicator--f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
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
    },
    {
        "type": "indicator",
        "id": "indicator--90bd7dae-b78c-4025-9073-568950c780fb",
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
    },
    {
        "type": "indicator",
        "id": "indicator--2007ec09-8137-4a71-a3ce-6ef967bebacf",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA256 test attribute",
        "pattern": "[file:hashes.SHA256 = '7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4']",
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
        "id": "indicator--c8760340-85a9-4e40-bfde-522d66ef1e9f",
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
    },
    {
        "type": "indicator",
        "id": "indicator--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "SHA512 test attribute",
        "pattern": "[file:hashes.SHA512 = '28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe']",
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
        "id": "indicator--9060e814-a36f-45ab-84e5-66fc82dc7cff",
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
    },
    {
        "type": "indicator",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "AUTHENTIHASH test attribute",
        "pattern": "[file:hashes.AUTHENTIHASH = 'b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc']",
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
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "IMPHASH test attribute",
        "pattern": "[file:hashes.IMPHASH = '68f013d7437aa653a8a98a05807afeb1']",
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
        "id": "indicator--94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "PEHASH test attribute",
        "pattern": "[file:hashes.PEHASH = 'ffb7a38174aab4744cc4a509e34800aee9be8e57']",
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
        "id": "indicator--2d35a390-ccdd-4d6b-a36d-513b05e3682a",
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
    },
    {
        "type": "indicator",
        "id": "indicator--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
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
    },
    {
        "type": "indicator",
        "id": "indicator--4846cade-2492-4e7d-856e-2afcd282455b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "TELFHASH test attribute",
        "pattern": "[file:hashes.TELFHASH = 'b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b']",
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
    },
    {
        "type": "indicator",
        "id": "indicator--7467406e-88d3-4856-afc9-412459bc3c8b",
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
    },
    {
        "type": "indicator",
        "id": "indicator--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "VHASH test attribute",
        "pattern": "[file:hashes.VHASH = '115056655d15151138z66hz1021z55z66z3']",
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
    }
]
_HASH_OBSERVABLE_ATTRIBUTES = [
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
                    "MD5": "b2a5abfeef9e36964281a31e17b57c97"
                }
            }
        },
        "labels": [
            "misp:type=\"md5\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-1": "2920d5e6c579fce772e5506caf03af65579088bd"
                }
            }
        },
        "labels": [
            "misp:type=\"sha1\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-224": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9"
                }
            }
        },
        "labels": [
            "misp:type=\"sha224\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-256": "7fa3abc229fd3cb9a0a6f07d9da15e35528c630d0ad5902d5422b305cae7eaa4"
                }
            }
        },
        "labels": [
            "misp:type=\"sha256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--c8760340-85a9-4e40-bfde-522d66ef1e9f",
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
    },
    {
        "type": "observed-data",
        "id": "observed-data--55ffda25-c3fe-48b5-a6eb-59c986cb593e",
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
                    "SHA-512": "28c9409ebaed767fe240ecacf727f9a5bd9f17fbd054f7dff2770a81878e56b176bf5f0cd196217ac785dd88e807a78ef3ee8b8122aba15c9ffb5c143794e6fe"
                }
            }
        },
        "labels": [
            "misp:type=\"sha512\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--9060e814-a36f-45ab-84e5-66fc82dc7cff",
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
    },
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
                    "AUTHENTIHASH": "b3b8b4ac8ac98e610c49b4c5306b95ea2836348492b5c488f584a223541283cc"
                }
            }
        },
        "labels": [
            "misp:type=\"authentihash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "IMPHASH": "68f013d7437aa653a8a98a05807afeb1"
                }
            }
        },
        "labels": [
            "misp:type=\"imphash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "PEHASH": "ffb7a38174aab4744cc4a509e34800aee9be8e57"
                }
            }
        },
        "labels": [
            "misp:type=\"pehash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
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
                    "SHA-256": "82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93"
                }
            }
        },
        "labels": [
            "misp:type=\"sha512/256\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--e9f3dab7-1c2d-43ca-8bf7-d49214ca81a6",
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
    },
    {
        "type": "observed-data",
        "id": "observed-data--4846cade-2492-4e7d-856e-2afcd282455b",
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
                    "TELFHASH": "b1217492227645186ff295285cbc827216226b2323597f71ff36c8cc453b0e5f539d0b"
                }
            }
        },
        "labels": [
            "misp:type=\"telfhash\"",
            "misp:category=\"Payload delivery\""
        ]
    },
    {
        "type": "observed-data",
        "id": "observed-data--7467406e-88d3-4856-afc9-412459bc3c8b",
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
    },
    {
        "type": "observed-data",
        "id": "observed-data--cea8c6f6-696c-41cc-b7c7-2566ca0b0975",
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
                    "VHASH": "115056655d15151138z66hz1021z55z66z3"
                }
            }
        },
        "labels": [
            "misp:type=\"vhash\"",
            "misp:category=\"Payload delivery\""
        ]
    }
]
_HOSTNAME_INDICATOR_ATTRIBUTE = {
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
_HOSTNAME_OBSERVABLE_ATTRIBUTE = {
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
_HOSTNAME_PORT_INDICATOR_ATTRIBUTE = {
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
_HOSTNAME_PORT_OBSERVABLE_ATTRIBUTE = {
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
_HTTP_INDICATOR_ATTRIBUTES = [
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
    },
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
]
_IMAGE_INDICATOR_OBJECT = {
    "type": "indicator",
    "id": "indicator--939b2f03-c487-4f62-a90e-cab7acfee294",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
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
_IMAGE_OBSERVABLE_OBJECT = {
    "type": "observed-data",
    "id": "observed-data--939b2f03-c487-4f62-a90e-cab7acfee294",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "first_observed": "2020-10-25T16:22:00Z",
    "last_observed": "2020-10-25T16:22:00Z",
    "number_observed": 1,
    "objects": {
        "0": {
            "type": "file",
            "name": "STIX.png",
            "content_ref": "1",
            "x_misp_image_text": "STIX"
        },
        "1": {
            "type": "artifact",
            "mime_type": "image/png",
            "x_misp_filename": "STIX.png",
            "x_misp_url": "https://oasis-open.github.io/cti-documentation/img/STIX.png"
        }
    },
    "labels": [
        "misp:name=\"image\"",
        "misp:meta-category=\"file\"",
        "misp:to_ids=\"False\""
    ]
}
_IP_INDICATOR_ATTRIBUTES = [
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
    },
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
]
_IP_OBSERVABLE_ATTRIBUTES = [
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
    },
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
]
_IP_PORT_INDICATOR_ATTRIBUTES = [
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
    },
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
]
_IP_PORT_INDICATOR_OBJECT = {
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
        "misp:name=\"ip-port\"",
        "misp:meta-category=\"network\"",
        "misp:to_ids=\"True\""
    ]
}
_IP_PORT_OBSERVABLE_ATTRIBUTES = [
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
    },
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
]
_IP_PORT_OBSERVABLE_OBJECT = {
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
                "ipv4"
            ],
            "x_misp_domain": "circl.lu"
        },
        "1": {
            "type": "ipv4-addr",
            "value": "149.13.33.14"
        }
    },
    "labels": [
        "misp:name=\"ip-port\"",
        "misp:meta-category=\"network\"",
        "misp:to_ids=\"False\""
    ]
}
_LEGAL_ENTITY_OBJECT = {
    "type": "identity",
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
_MAC_ADDRESS_OBSERVABLE_ATTRIBUTE = {
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
_MALWARE_SAMPLE_INDICATOR_ATTRIBUTE = {
    "type": "indicator",
    "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "description": "Malware Sample test attribute",
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
_MALWARE_SAMPLE_OBSERVABLE_ATTRIBUTE = {
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
            "mime_type": "application/zip"
        }
    },
    "labels": [
        "misp:type=\"malware-sample\"",
        "misp:category=\"Payload delivery\""
    ]
}
_MUTEX_INDICATOR_ATTRIBUTE = {
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
_MUTEX_OBSERVABLE_ATTRIBUTE = {
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
_NEWS_AGENCY_OBJECT = {
    "type": "identity",
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
        "value": "AFP_logo.png"
    },
    "x_misp_link": "https://www.afp.com/"
}
_ORGANIZATION_OBJECT = {
    "type": "identity",
    "id": "identity--fe85995c-189d-4c20-9d0e-dfc03e72000b",
    "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
    "created": "2020-10-25T16:22:00.000Z",
    "modified": "2020-10-25T16:22:00.000Z",
    "name": "Computer Incident Response Center of Luxembourg",
    "description": "The Computer Incident Response Center Luxembourg (CIRCL) is a government-driven initiative designed to gather, review, report and respond to computer security threats and incidents.",
    "identity_class": "organization",
    "contact_information": "address: 16, bd d'Avranches, L-1160 Luxembourg / e-mail: info@circl.lu / phone-number: (+352) 247 88444",
    "labels": [
        "misp:name=\"organization\"",
        "misp:meta-category=\"misc\"",
        "misp:to_ids=\"False\""
    ],
    "x_misp_alias": "CIRCL",
    "x_misp_role": "national CERT"
}
_PORT_INDICATOR_ATTRIBUTE = {
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
_REGKEY_INDICATOR_ATTRIBUTE = {
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
_REGKEY_OBSERVABLE_ATTRIBUTE = {
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
_REGKEY_VALUE_INDICATOR_ATTRIBUTE = {
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
_REGKEY_VALUE_OBSERVABLE_ATTRIBUTE = {
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
_SIZE_IN_BYTES_INDICATOR_ATTRIBUTE = {
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
_SCRIPT_OBJECTS = [
    {
        "type": "malware",
        "id": "malware--ce12c406-cf09-457b-875a-41ab75d6dc4d",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "name": "infected.py",
        "description": "A script that infects command line shells",
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
        "implementation_languages": [
            "Python"
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
_URL_INDICATOR_ATTRIBUTES = [
    {
        "type": "indicator",
        "id": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "Link test attribute",
        "pattern": "[url:value = 'https://misp-project.org/download/']",
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
        "id": "indicator--518b4bcb-a86b-4783-9457-391d548b605b",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "URI test attribute",
        "pattern": "[url:value = 'https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova']",
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
        "id": "indicator--34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
        "created": "2020-10-25T16:22:00.000Z",
        "modified": "2020-10-25T16:22:00.000Z",
        "description": "URL test attribute",
        "pattern": "[url:value = 'https://vm.misp-project.org/latest/']",
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
            "misp:type=\"link\"",
            "misp:category=\"External analysis\""
        ]
    },
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
                "type": "url",
                "value": "https://vm.misp-project.org/latest/MISP_v2.4.155@ca03678.ova"
            }
        },
        "labels": [
            "misp:type=\"uri\"",
            "misp:category=\"Network activity\""
        ]
    },
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
                "type": "url",
                "value": "https://vm.misp-project.org/latest/"
            }
        },
        "labels": [
            "misp:type=\"url\"",
            "misp:category=\"Network activity\""
        ]
    }
]
_VULNERABILITY_ATTRIBUTE = {
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
_VULNERABILITY_OBJECT = {
    "type": "vulnerability",
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
    },
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
    },
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
]
_X509_FINGERPRINT_OBSERVABLE_ATTRIBUTES = [
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
    },
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
    },
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
]


class TestSTIX20Bundles:
    __bundle = {
        "type": "bundle",
        "id": "bundle--314e4210-e41a-4952-9f3c-135d7d577112",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "identity",
                "id": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "MISP-Project",
                "identity_class": "organization"
            },
            {
                "type": "report",
                "id": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "MISP-STIX-Converter test event",
                "published": "2020-10-25T16:22:00Z",
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
        return cls.__assemble_bundle(_AS_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_attachment_indicator_attribute(cls):
        return cls.__assemble_bundle(_ATTACHMENT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_attachment_observable_attribute(cls):
        return cls.__assemble_bundle(_ATTACHMENT_OBSERVABLE_ATTRIBUTE)

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
        return cls.__assemble_bundle(_DOMAIN_IP_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_domain_observable_attribute(cls):
        return cls.__assemble_bundle(_DOMAIN_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_attachment_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_ATTACHMENT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_attachment_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_ATTACHMENT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_body_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_BODY_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_body_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_BODY_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_destination_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_DESTINATION_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_destination_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_DESTINATION_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_header_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_HEADER_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_header_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_HEADER_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_reply_to_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_REPLY_TO_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_reply_to_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_REPLY_TO_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_source_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SOURCE_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_source_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SOURCE_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_subject_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SUBJECT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_subject_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_SUBJECT_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_x_mailer_indicator_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_X_MAILER_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_email_x_mailer_observable_attribute(cls):
        return cls.__assemble_bundle(_EMAIL_X_MAILER_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_filename_indicator_attribute(cls):
        return cls.__assemble_bundle(_FILENAME_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_filename_observable_attribute(cls):
        return cls.__assemble_bundle(_FILENAME_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_github_username_indicator_attribute(cls):
        return cls.__assemble_bundle(_GITHUB_USERNAME_INDICATOR_ATTRIBUTE)

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
        return cls.__assemble_bundle(_HOSTNAME_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hostname_port_indicator_attribute(cls):
        return cls.__assemble_bundle(_HOSTNAME_PORT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_hostname_port_observable_attribute(cls):
        return cls.__assemble_bundle(_HOSTNAME_PORT_OBSERVABLE_ATTRIBUTE)

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
        return cls.__assemble_bundle(_MAC_ADDRESS_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_malware_sample_indicator_attribute(cls):
        indicator = deepcopy(_MALWARE_SAMPLE_INDICATOR_ATTRIBUTE)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            pattern = [
                "file:name = 'oui'",
                "file:hashes.MD5 = '8764605c6f388c89096b534d33565802'",
                f"file:content_ref.payload_bin = '{b64encode(f.read()).decode()}'",
                "file:content_ref.mime_type = 'application/zip'"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_malware_sample_observable_attribute(cls):
        observed_data = deepcopy(_MALWARE_SAMPLE_OBSERVABLE_ATTRIBUTE)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observed_data['objects']['1']['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(observed_data)

    @classmethod
    def get_bundle_with_mutex_indicator_attribute(cls):
        return cls.__assemble_bundle(_MUTEX_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_mutex_observable_attribute(cls):
        return cls.__assemble_bundle(_MUTEX_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_port_indicator_attribute(cls):
        return cls.__assemble_bundle(_PORT_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_indicator_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_observable_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_OBSERVABLE_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_value_indicator_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_VALUE_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_regkey_value_observable_attribute(cls):
        return cls.__assemble_bundle(_REGKEY_VALUE_OBSERVABLE_ATTRIBUTE)

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
                f"user-account:x_misp_profile_photo.data = '{data}'","user-account:x_misp_profile_photo.value = 'octocat.png'"
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
                "user-account:user_id = 'iglocska'",
                "user-account:account_login = 'iglocska'",
                "user-account:password_last_changed = '2020-10-25T16:22:00'",
                "user-account:extensions.'unix-account-ext'.groups = 'viktor-fan'",
                "user-account:extensions.'unix-account-ext'.groups = 'donald-fan'",
                "user-account:extensions.'unix-account-ext'.gid = '2004'",
                "user-account:extensions.'unix-account-ext'.home_dir = '/home/iglocska'",
                "user-account:x_misp_password = 'P4ssw0rd1234!'",
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
        for observed_data, feature in zip(observables, features):
            observed_data['objects']['0'][feature]['data'] = data
        return cls.__assemble_bundle(*observables)

    @classmethod
    def get_bundle_with_asn_indicator_object(cls):
        return cls.__assemble_bundle(_ASN_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_asn_observable_object(cls):
        return cls.__assemble_bundle(_ASN_OBSERVABLE_OBJECT)

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
        return cls.__assemble_bundle(_CPE_ASSET_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_credential_indicator_object(cls):
        return cls.__assemble_bundle(_CREDENTIAL_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_credential_observable_object(cls):
        return cls.__assemble_bundle(_CREDENTIAL_OBSERVABLE_OBJECT)

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
        return cls.__assemble_bundle(_EMAIL_OBSERVABLE_OBJECT)

    @classmethod
    def get_bundle_with_employee_object(cls):
        return cls.__assemble_bundle(_EMPLOYEE_OBJECT)

    @classmethod
    def get_bundle_with_file_and_pe_indicator_object(cls):
        return cls.__assemble_bundle(_FILE_AND_PE_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_file_and_pe_observable_object(cls):
        return cls.__assemble_bundle(_FILE_AND_PE_OBSERVABLE_OBJECT)

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
                "file:content_ref.mime_type = 'application/zip')",
                "(file:content_ref.payload_bin = 'Tm9uLW1hbGljaW91cyBmaWxlCg=='",
                "file:content_ref.x_misp_filename = 'non')"
            ]
        indicator['pattern'] = f"[{' AND '.join(pattern)}]"
        return cls.__assemble_bundle(indicator)

    @classmethod
    def get_bundle_with_file_observable_object(cls):
        observed_data = deepcopy(_FILE_OBSERVABLE_OBJECT)
        with open(_TESTFILES_PATH / 'malware_sample.zip', 'rb') as f:
            observed_data['objects']['2']['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(observed_data)

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
        observed_data = deepcopy(_IMAGE_OBSERVABLE_OBJECT)
        with open(_TESTFILES_PATH / 'STIX_logo.png', 'rb') as f:
            observed_data['objects']['1']['payload_bin'] = b64encode(f.read()).decode()
        return cls.__assemble_bundle(observed_data)

    @classmethod
    def get_bundle_with_ip_port_indicator_object(cls):
        return cls.__assemble_bundle(_IP_PORT_INDICATOR_OBJECT)

    @classmethod
    def get_bundle_with_ip_port_observable_object(cls):
        return cls.__assemble_bundle(_IP_PORT_OBSERVABLE_OBJECT)

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
    def get_bundle_with_script_objects(cls):
        return cls.__assemble_bundle(*_SCRIPT_OBJECTS)

    @classmethod
    def get_bundle_with_vulnerability_object(cls):
        return cls.__assemble_bundle(_VULNERABILITY_OBJECT)
