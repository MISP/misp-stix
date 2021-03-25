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
Now we can have a look at the results when we add attributes, objects, galaxies, or tags (**TLinks to the detailed mappings for each structure type are available below**).

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
- Event with attribute(s) or object(s) producing indicator(s)
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

- Event with attribute(s) or object(s) producing observable(s)
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

Those examples provide a simple overview of the events mapping as STIX 2.0.  
For more information about the mapping as STIX 2.0, please find above the detailed mappings for attributes, objects and galaxies export.

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Attributes export to STIX 2.1 mapping](misp_attributes_to_stix21.md)
- [Objects export to STIX 2.1 mapping](misp_objects_to_stix21.md)
- [Galaxies export to STIX 2.1 mapping](misp_galaxies_to_stix21.md)

([Go back to the main documentation](README.md))
