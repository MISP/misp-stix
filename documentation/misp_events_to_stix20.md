# Events mapping

MISP Events are exported within STIX Bundles and some of the metadata fields are embedded within Report objects:
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--a89e43b6-601d-43b4-b040-d7cf04ba0c37",
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
                "object_refs": [
                    "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "x-misp-event-note",
                "id": "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "object_ref": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "x_misp_event_note": "This MISP Event is empty and contains no attribute, object or galaxy."
            }
        ]
    }
    ```

This is a very basic example to show how the MISP Event fields are ported into STIX 2.0, but let us see now what happens when we start adding data to the event or change some fields value:
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--7d5d1bf8-1dca-4508-ae85-b581e746c921",
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
                "published": "2020-10-25T16:22:30Z",
                "object_refs": [
                    "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
                ]
            },
            {
                "type": "x-misp-event-note",
                "id": "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "object_ref": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "x_misp_event_note": "This MISP Event is empty and contains no attribute, object or galaxy."
            }
        ]
    }
    ```

We can already see the published timestamp is exported as well when the event is published.  
Now we can have a look at the results when we add attributes, objects, galaxies, or tags (**Links to the detailed mappings for each structure type are available below**).

Exporting tags is pretty much straight forward and does not require a complex mapping.  
Nonetheless, with STIX 2.0 and STIX2 in general, `Marking` objects only support the `tlp` and the `statement` definition type. Thus, with the following example you can see that out of the 4 different tags, only one is exported in a `Marking` object, and the other one are set as labels.
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--7d5d1bf8-1dca-4508-ae85-b581e746c921",
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
                "object_refs": [
                    "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c"
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
                "type": "x-misp-event-note",
                "id": "x-misp-event-note--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "created_by_ref": "identity--a0c22599-9e58-4da4-96ac-7051603fa951",
                "created": "2020-10-25T16:22:00.000Z",
                "modified": "2020-10-25T16:22:00.000Z",
                "object_ref": "report--a6ef17d6-91cb-4a05-b10b-2f045daf874c",
                "x_misp_event_note": "This MISP Event is empty and contains no attribute, object or galaxy."
            },
            {
                "type": "marking-definition",
                "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--7d5d1bf8-1dca-4508-ae85-b581e746c921",
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
                "published": "2020-10-25T16:22:30Z",
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--a468c0dc-0698-434c-8a09-62748df8ae63",
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
  - STIX 2.0
    ```json
    {
        "type": "bundle",
        "id": "bundle--02620277-7e88-4203-a32e-d621b3a7cda4",
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
                "object_refs": [
                    "observed-data--91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"
                ],
                "labels": [
                    "Threat-Report",
                    "misp:tool=\"MISP-STIX-Converter\""
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
                        "type": "domain-name",
                        "value": "circl.lu"
                    }
                },
                "labels": [
                    "misp:type=\"domain\"",
                    "misp:category=\"Network activity\""
                ]
            }
        ]
    }
    ```

Those examples provide a simple overview of the events mapping as STIX 2.0.  
For more information about the mapping as STIX 2.0, please find above the detailed mappings for attributes, objects and galaxies export.

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Attributes export to STIX 2.0 mapping](misp_attributes_to_stix20.md)
- [Objects export to STIX 2.0 mapping](misp_objects_to_stix20.md)
- [Galaxies export to STIX 2.0 mapping](misp_galaxies_to_stix20.md)

([Go back to the main documentation](README.md))
