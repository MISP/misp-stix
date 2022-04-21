#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from copy import deepcopy
from pathlib import Path
from stix2.parsing import dict_to_stix2

_TESTFILES_PATH = Path(__file__).parent.resolve() / 'attachment_test_files'
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
    "pattern": "[file:name = 'oui' AND file:hashes.MD5 = '8764605c6f388c89096b534d33565802' AND file:content_ref.payload_bin = 'UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==' AND file:content_ref.mime_type = 'application/zip']",
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
            "mime_type": "application/zip",
            "payload_bin": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA=="
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
    #                               ATTRIBUTES TESTS                               #
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
        return cls.__assemble_bundle(_MALWARE_SAMPLE_INDICATOR_ATTRIBUTE)

    @classmethod
    def get_bundle_with_malware_sample_observable_attribute(cls):
        return cls.__assemble_bundle(_MALWARE_SAMPLE_OBSERVABLE_ATTRIBUTE)

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
    #                              MISP OBJECTS TESTS                              #
    ################################################################################

    @classmethod
    def get_bundle_with_attack_pattern_object(cls):
        return cls.__assemble_bundle(_ATTACK_PATTERN_OBJECT)

    @classmethod
    def get_bundle_with_course_of_action_object(cls):
        return cls.__assemble_bundle(_COURSE_OF_ACTION_OBJECT)

    @classmethod
    def get_bundle_with_employee_object(cls):
        return cls.__assemble_bundle(_EMPLOYEE_OBJECT)

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