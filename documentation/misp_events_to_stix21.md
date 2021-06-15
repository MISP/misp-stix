# Events mapping

MISP Events are exported within STIX packages, where some of the metadata fields are embedded within incidents:
- Base event
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [],
            "Object": [],
            "Galaxy": [],
            "Tag": []
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--eeaf76e5-12fc-4272-aff0-9e9accd36acf",
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
                "object_refs": [
                    "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "note",
                "spec_version": "2.1",
                "id": "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "content": "This MISP Event is empty and contains no attribute, object or galaxy.",
                "object_refs": [
                    "grouping--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ]
            }
        ]
    }
    ```

This is a very basic example to show how the MISP Event fields are ported into STIX 2.1, but let us see now what happens when we start adding data to the event or change some fields value:
- Published event
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [],
            "Object": [],
            "Galaxy": [],
            "Tag": [],
            "published": true,
            "publish_timestamp": "1603642950"
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--60be01f8-9e95-48d2-a1b6-f70ca27857cf",
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
                "type": "report",
                "spec_version": "2.1",
                "id": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "MISP-STIX-Converter test event",
                "published": "2020-10-25T16:22:30Z",
                "object_refs": [
                    "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "note",
                "spec_version": "2.1",
                "id": "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "content": "This MISP Event is empty and contains no attribute, object or galaxy.",
                "object_refs": [
                    "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ]
            }
        ]
    }
    ```

We can already see the published timestamp is exported as well when the event is published and instead of a `Grouping` object, the event metadata fields are exported with a `Report` object.  
Now we can have a look at the results when we add attributes, objects, galaxies, or tags (**Links to the detailed mappings for each structure type are available below**).

Exporting tags is pretty much straight forward and does not require a complex mapping.  
Nonetheless, with STIX 2.1 and STIX2 in general, `Marking` objects only support the `tlp` and the `statement` definition type. Thus, with the following example you can see that out of the 4 different tags, only one is exported in a `Marking` object, and the other one are set as labels.
- Event with tags
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [],
            "Object": [],
            "Galaxy": [],
            "Tag": [
                {
                    "name": "tlp:white"
                },
                {
                    "name": "misp:tool=\"misp2stix\""
                },
                {
                    "name": "misp-galaxy:mitre-attack-pattern=\"Code Signing - T1116\""
                },
                {
                    "name": "misp-galaxy:mitre-attack-pattern=\"Access Token Manipulation - T1134\""
                }
            ],
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--60be01f8-9e95-48d2-a1b6-f70ca27857cf",
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
                "type": "report",
                "spec_version": "2.1",
                "id": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "MISP-STIX-Converter test event",
                "published": "2020-10-25T16:22:00Z",
                "object_refs": [
                    "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\"",
                    "misp:tool=\"misp2stix\"",
                    "misp-galaxy:mitre-attack-pattern=\"Code Signing - T1116\"",
                    "misp-galaxy:mitre-attack-pattern=\"Access Token Manipulation - T1134\""
                ],
                "object_marking_refs": [
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                ]
            },
            {
                "type": "note",
                "spec_version": "2.1",
                "id": "note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "content": "This MISP Event is empty and contains no attribute, object or galaxy.",
                "object_refs": [
                    "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ]
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
    }
    ```

As shown with this example, tags are basically exported as marking structures.

If you are familiar with the MISP format, you can already see there are some tags representing MISP galaxies, because galaxies are referenced in the tags where their definition is embedded within the `Galaxy` field.  
With the next example we will see that every galaxy actually included in the event and referenced within the tags is exported as any galaxy (detailed mapping available below) and no longer as tag only:  
`misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"` is the tag name for the mitre-attack-pattern galaxy `Access Token Manipulation - T1134` and is in the list of tags, but exported as a galaxy since it is included in the galaxies, but `misp-galaxy:mitre-attack-pattern="Code Signing - T1116"` is only a tag.
- Event with galaxy
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [],
            "Object": [],
            "Galaxy": [
                {
                    "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
                    "name": "Attack Pattern",
                    "type": "mitre-attack-pattern",
                    "description": "ATT&CK Tactic",
                    "GalaxyCluster": [
                        {
                            "uuid": "dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                            "value": "Access Token Manipulation - T1134",
                            "description": "Windows uses access tokens to determine the ownership of a running process.",
                            "meta": {
                                "external_id": [
                                    "CAPEC-633"
                                ]
                            }
                        }
                    ]
                }
            ],
            "Tag": [
                {
                    "name": "misp-galaxy:mitre-attack-pattern=\"Code Signing - T1116\""
                },
                {
                    "name": "misp-galaxy:mitre-attack-pattern=\"Access Token Manipulation - T1134\""
                }
            ],
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--88e63d00-8eee-4c85-9141-f0702698ed26",
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
                "object_refs": [
                    "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\"",
                    "misp-galaxy:mitre-attack-pattern=\"Code Signing - T1116\""
                ]
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "Access Token Manipulation - T1134",
                "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-attack-pattern"
                    }
                ],
                "labels": [
                    "misp:name=\"Attack Pattern\""
                ]
            }
        ]
    }
    ```

Exporting attributes differs from exporting objects in terms of complexity of the parsing, but both result in the creation of `Indicators` or `Observable` in most cases. The parameter that triggers one or the other case is simply the `to_ids` flag:
- Event with attribute(s) or object(s) exported as indicator(s)
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [
                {
                    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "circl.lu",
                    "timestamp": "1603642920",
                    "comment": "Domain test attribute",
                    "to_ids": true
                }
            ],
            "Object": [],
            "Galaxy": [],
            "Tag": []
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--7c23d0ff-4c95-48f4-9353-2f59915d656a",
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
                "object_refs": [
                    "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
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
            }
        ]
    }
    ```

- Event with attribute(s) or object(s) exported as observable(s)
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2020-10-25",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP"
            },
            "Orgc": {
                "name": "MISP"
            },
            "Attribute": [
                {
                    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "circl.lu",
                    "timestamp": "1603642920",
                    "comment": "Domain test attribute",
                    "to_ids": false
                }
            ],
            "Object": [],
            "Galaxy": [],
            "Tag": []
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--c1cb4137-d45d-4ca9-8b17-75daf6de4bfe",
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
                "object_refs": [
                    "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                    "domain-name--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
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
    }
    ```

Embedded galaxies also trigger some specific computation in order to build the corresponding references between the different STIX 2.1 objects.  
- With galaxies embedded in attributes, the result is STIX objects directly linked together with a `Relationship` object which describes the link between the object generated from an attribute and the object generated from a galaxy:
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2021-06-15",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Orgc": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Attribute": [
                {
                    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "circl.lu",
                    "timestamp": "1603642920",
                    "comment": "Domain test attribute",
                    "to_ids": true,
                    "Galaxy": [
                        {
                            "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
                            "name": "Attack Pattern",
                            "type": "mitre-attack-pattern",
                            "description": "ATT&CK Tactic",
                            "GalaxyCluster": [
                                {
                                    "uuid": "dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                                    "type": "mitre-attack-pattern",
                                    "value": "Access Token Manipulation - T1134",
                                    "description": "Windows uses access tokens to determine the ownership of a running process.",
                                    "meta": {
                                        "external_id": [
                                            "CAPEC-633"
                                        ]
                                    }
                                }
                            ]
                        },
                        {
                            "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e",
                            "name": "Course of Action",
                            "type": "mitre-course-of-action",
                            "description": "ATT&CK Mitigation",
                            "GalaxyCluster": [
                                {
                                    "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
                                    "type": "mitre-course-of-action",
                                    "value": "Automated Exfiltration Mitigation - T1020",
                                    "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
                                }
                            ]
                        }
                    ]
                }
            ],
            "Object": [],
            "Galaxy": [
                {
                    "uuid": "d752161c-78f6-11e7-a0ea-bfa79b407ce4",
                    "name": "Malware",
                    "type": "mitre-malware",
                    "description": "Name of ATT&CK software",
                    "GalaxyCluster": [
                        {
                            "uuid": "b8eb28e4-48a6-40ae-951a-328714f75eda",
                            "type": "mitre-malware",
                            "value": "BISCUIT - S0017",
                            "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
                            "meta": {
                                "synonyms": [
                                    "BISCUIT"
                                ]
                            }
                        }
                    ]
                }
            ],
            "Tag": []
        }
    }
    ```
    - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--716b9bbb-131c-4ec4-b9bd-6d977dbf6ca2",
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
                "object_refs": [
                    "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                    "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
                    "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                    "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
                    "relationship--8d35e097-7589-4b80-81df-999c041c3d4b",
                    "relationship--dfc99c49-d8b7-467c-8255-cabe8458d084"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "Access Token Manipulation - T1134",
                "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-attack-pattern"
                    }
                ],
                "labels": [
                    "misp:name=\"Attack Pattern\""
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
                    "misp:name=\"Course of Action\""
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
                "is_family": true,
                "aliases": [
                    "BISCUIT"
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-malware"
                    }
                ],
                "labels": [
                    "misp:name=\"Malware\""
                ]
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--8d35e097-7589-4b80-81df-999c041c3d4b",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "target_ref": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--dfc99c49-d8b7-467c-8255-cabe8458d084",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "has",
                "source_ref": "indicator--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "target_ref": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294"
            }
        ]
    }
    ```
    As we can see here, there is a Galaxy coming with the event, which is simply exported in a STIX object, and other Galaxies embedded in attributes.  
    Those only are the ones concerned by `Relationship` objects.

- Galaxies can also be embedded in objects attributes, in which case the complete MISP object is exported in a single STIX object. The embedded galaxies are then extracted, exported as STIX objects, and all linked to the same STIX object (the one generated from the MISP object export):
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2021-06-15",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Orgc": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Attribute": [],
            "Object": [
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
                            "value": "Block traffic to PIVY C2 Server (10.10.10.10)",
                            "Galaxy": [
                                {
                                    "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
                                    "name": "Attack Pattern",
                                    "type": "mitre-attack-pattern",
                                    "description": "ATT&CK Tactic",
                                    "GalaxyCluster": [
                                        {
                                            "uuid": "dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                                            "type": "mitre-attack-pattern",
                                            "value": "Access Token Manipulation - T1134",
                                            "description": "Windows uses access tokens to determine the ownership of a running process.",
                                            "meta": {
                                                "external_id": [
                                                    "CAPEC-633"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "type": "text",
                            "object_relation": "type",
                            "value": "Perimeter Blocking",
                            "Galaxy": [
                                {
                                    "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e",
                                    "name": "Course of Action",
                                    "type": "mitre-course-of-action",
                                    "description": "ATT&CK Mitigation",
                                    "GalaxyCluster": [
                                        {
                                            "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
                                            "type": "mitre-course-of-action",
                                            "value": "Automated Exfiltration Mitigation - T1020",
                                            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
                                        }
                                    ]
                                }
                            ]
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
                },
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
                            "value": "CVE-2017-11774",
                            "Galaxy": [
                                {
                                    "uuid": "d752161c-78f6-11e7-a0ea-bfa79b407ce4",
                                    "name": "Malware",
                                    "type": "mitre-malware",
                                    "description": "Name of ATT&CK software",
                                    "GalaxyCluster": [
                                        {
                                            "uuid": "b8eb28e4-48a6-40ae-951a-328714f75eda",
                                            "type": "mitre-malware",
                                            "value": "BISCUIT - S0017",
                                            "description": "BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
                                            "meta": {
                                                "synonyms": [
                                                    "BISCUIT"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "type": "float",
                            "object_relation": "cvss-score",
                            "value": "6.8",
                            "Galaxy": [
                                {
                                    "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e",
                                    "name": "Course of Action",
                                    "type": "mitre-course-of-action",
                                    "description": "ATT&CK Mitigation",
                                    "GalaxyCluster": [
                                        {
                                            "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
                                            "type": "mitre-course-of-action",
                                            "value": "Automated Exfiltration Mitigation - T1020",
                                            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
                                        }
                                    ]
                                }
                            ]
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
            ],
            "Galaxy": [
                {
                    "uuid": "6fcb4472-6de4-11e7-b5f7-37771619e14e",
                    "name": "Course of Action",
                    "type": "mitre-course-of-action",
                    "description": "ATT&CK Mitigation",
                    "GalaxyCluster": [
                        {
                            "uuid": "2497ac92-e751-4391-82c6-1b86e34d0294",
                            "type": "mitre-course-of-action",
                            "value": "Automated Exfiltration Mitigation - T1020",
                            "description": "Identify unnecessary system utilities, scripts, or potentially malicious software that may be used to transfer data outside of a network"
                        }
                    ]
                },
                {
                    "uuid": "d5cbd1a2-78f6-11e7-a833-7b9bccca9649",
                    "name": "Tool",
                    "type": "mitre-tool",
                    "description": "Name of ATT&CK software",
                    "GalaxyCluster": [
                        {
                            "uuid": "bba595da-b73a-4354-aa6c-224d4de7cb4e",
                            "type": "mitre-tool",
                            "value": "cmd - S0106",
                            "description": "cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
                            "meta": {
                                "synonyms": [
                                    "cmd.exe"
                                ]
                            }
                        }
                    ]
                }
            ],
            "Tag": []
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--efb7e6d0-5e44-431e-a1b5-25794eeee507",
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
                "object_refs": [
                    "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                    "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294",
                    "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
                    "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
                    "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
                    "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
                    "relationship--37dafe08-71b3-49d2-b41f-33b97651c2d5",
                    "relationship--a34ae387-b180-47e0-9264-9645e748eb05",
                    "relationship--e9c6b6bc-9e07-4c73-8dfe-dbf526d4a6f8",
                    "relationship--e4a3ba6b-58a9-49bd-a863-378b4cca77d1"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "Access Token Manipulation - T1134",
                "description": "ATT&CK Tactic | Windows uses access tokens to determine the ownership of a running process.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-attack-pattern"
                    }
                ],
                "labels": [
                    "misp:name=\"Attack Pattern\""
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
                    "misp:name=\"Course of Action\""
                ]
            },
            {
                "type": "course-of-action",
                "spec_version": "2.1",
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
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "BISCUIT - S0017",
                "description": "Name of ATT&CK software | BISCUIT is a backdoor that has been used by APT1 since as early as 2007.",
                "is_family": true,
                "aliases": [
                    "BISCUIT"
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-malware"
                    }
                ],
                "labels": [
                    "misp:name=\"Malware\""
                ]
            },
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2017-10-13T07:29:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
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
            },
            {
                "type": "tool",
                "spec_version": "2.1",
                "id": "tool--bba595da-b73a-4354-aa6c-224d4de7cb4e",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "name": "cmd - S0106",
                "description": "Name of ATT&CK software | cmd is the Windows command-line interpreter that can be used to interact with systems and execute other processes and utilities.",
                "aliases": [
                    "cmd.exe"
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "misp-category",
                        "phase_name": "mitre-tool"
                    }
                ],
                "labels": [
                    "misp:name=\"Tool\""
                ]
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--37dafe08-71b3-49d2-b41f-33b97651c2d5",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
                "target_ref": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--a34ae387-b180-47e0-9264-9645e748eb05",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "has",
                "source_ref": "course-of-action--5d514ff9-ac30-4fb5-b9e7-3eb4a964451a",
                "target_ref": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--e9c6b6bc-9e07-4c73-8dfe-dbf526d4a6f8",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "has",
                "source_ref": "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
                "target_ref": "malware--b8eb28e4-48a6-40ae-951a-328714f75eda"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--e4a3ba6b-58a9-49bd-a863-378b4cca77d1",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "has",
                "source_ref": "vulnerability--5e579975-e9cc-46c6-a6ad-1611a964451a",
                "target_ref": "course-of-action--2497ac92-e751-4391-82c6-1b86e34d0294"
            }
        ]
    }
    ```
    In this case we can see all the relationships are actually describing the relation of exported galaxies being embedded in MISP objects attributes.  
    Some relationship types between two STIX objects are defined by the format itself, and we simply check if the two objects involved in the relationship are matching those defined relationships (for instance with the example above, a `Course of Action` mitigates an `Attack Pattern`).

There is ultimately a last specific use case to mention: the references between MISP Objects.  
- With the last examples we saw relationships describing the logical relation that links two STIX objects when they were initially embedded one in the other. Now the use case is a MISP object with a reference to another MISP object:
  - MISP
    ```json
    {
        "Event": {
            "uuid": "a6ef17d6-91cb-4a05-b10b-2f045daf874c",
            "info": "MISP-STIX-Converter test event",
            "date": "2021-06-15",
            "timestamp": "1603642920",
            "Org": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Orgc": {
                "name": "MISP-Project",
                "uuid": "a0c22599-9e58-4da4-96ac-7051603fa951"
            },
            "Attribute": [],
            "Object": [
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
                    ],
                    "ObjectReference": [
                        {
                            "referenced_uuid": "5ac47edc-31e4-4402-a7b6-040d0a00020f",
                            "relationship_type": "includes"
                        }
                    ]
                },
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
                            "value": "149.13.33.14",
                            "to_ids": true
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
                },
                {
                    "name": "vulnerability",
                    "meta-category": "vulnerability",
                    "description": "Vulnerability object describing a common vulnerability",
                    "uuid": "651a981f-6f59-4609-b735-e57efb9d44df",
                    "timestamp": "1603642920",
                    "Attribute": [
                        {
                            "type": "vulnerability",
                            "object_relation": "id",
                            "value": "CVE-2021-29921"
                        },
                        {
                            "type": "text",
                            "object_relation": "summary",
                            "value": "In Python before 3.9.5, the ipaddress library mishandles leading zero characters in the octets of an IP address string."
                        }
                    ],
                    "ObjectReference": [
                        {
                            "referenced_uuid": "5ac47edc-31e4-4402-a7b6-040d0a00020f",
                            "relationship_type": "affects"
                        }
                    ]
                }
            ],
            "Galaxy": [],
            "Tag": []
        }
    }
    ```
  - STIX
    ```json
    {
        "type": "bundle",
        "id": "bundle--1c1ad95f-2733-4469-b15d-38072eedeead",
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
                "object_refs": [
                    "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
                    "autonomous-system--52edeb5f-e79a-5775-938c-de02f26c9ce6",
                    "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f",
                    "vulnerability--651a981f-6f59-4609-b735-e57efb9d44df",
                    "relationship--0c8c64ee-2c52-4222-ace9-6a495c6f0e91",
                    "relationship--40ed3e91-d887-42ad-8eb3-5ec68e80b77c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
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
                    "autonomous-system--52edeb5f-e79a-5775-938c-de02f26c9ce6"
                ],
                "labels": [
                    "misp:category=\"network\"",
                    "misp:name=\"asn\"",
                    "misp:to_ids=\"False\""
                ]
            },
            {
                "type": "autonomous-system",
                "spec_version": "2.1",
                "id": "autonomous-system--52edeb5f-e79a-5775-938c-de02f26c9ce6",
                "number": 66642,
                "name": "AS name",
                "x_misp_subnet_announced": [
                    "1.2.3.4",
                    "8.8.8.8"
                ]
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
                    "misp:category=\"network\"",
                    "misp:name=\"ip-port\"",
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
                    "misp:category=\"vulnerability\"",
                    "misp:name=\"vulnerability\""
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
                "id": "relationship--0c8c64ee-2c52-4222-ace9-6a495c6f0e91",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "includes",
                "source_ref": "observed-data--5b23c82b-6508-4bdc-b580-045b0a00020f",
                "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--40ed3e91-d887-42ad-8eb3-5ec68e80b77c",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "relationship_type": "affects",
                "source_ref": "vulnerability--651a981f-6f59-4609-b735-e57efb9d44df",
                "target_ref": "indicator--5ac47edc-31e4-4402-a7b6-040d0a00020f"
            }
        ]
    }
    ```
    As we can see here, the `Relationship` objects are used to describe the references between two MISP object exported as STIX objects as well.  
    There is an exception to this behavior with the references between a `file` object and its included `pe` object with the related `pe-section` objects, which is documented in the Objects export documentation (link below).

Those examples provide a simple overview of the events mapping as STIX 2.1.  
For more information about the mapping as STIX 2.1, please find above the detailed mappings for attributes, objects and galaxies export.

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Attributes export to STIX 2.1 mapping](misp_attributes_to_stix21.md)
- [Objects export to STIX 2.1 mapping](misp_objects_to_stix21.md)
- [Galaxies export to STIX 2.1 mapping](misp_galaxies_to_stix21.md)

([Go back to the main documentation](README.md))
