# Events mapping

MISP Events are exported within STIX packages, where some of the metadata fields are embedded within incidents:
- Base event
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
    ```xml
    <stix:STIX_Package id="MISP:STIXPackage-91b18402-618a-4818-8432-4ab41ec8b890" version="1.1.1" timestamp="2020-10-25T16:22:00+00:00">
        <stix:STIX_Header>
            <stix:Title>Export from MISP MISP</stix:Title>
        </stix:STIX_Header>
        <stix:Incidents>
            <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T16:22:00+00:00" xsi:type='incident:IncidentType'>
                <incident:Title>MISP-STIX-Converter test event</incident:Title>
                <incident:Time>
                    <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
                </incident:Time>
                <incident:Reporter>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Reporter>
                <incident:Information_Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Information_Source>
            </stix:Incident>
        </stix:Incidents>
    </stix:STIX_Package>
    ```

This is a very basic example to show how the MISP Event fields are ported into STIX, but let us see now what happens when we start adding data to the event or change some fields value:
- Published event
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
            "publish_timestamp": "1603642920"
        }
    }
    ```
  - STIX
    ```xml
    <stix:STIX_Package id="MISP:STIXPackage-91b18402-618a-4818-8432-4ab41ec8b890" version="1.1.1" timestamp="2020-10-25T16:22:00+00:00">
        <stix:STIX_Header>
            <stix:Title>Export from MISP MISP</stix:Title>
        </stix:STIX_Header>
        <stix:Incidents>
            <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T16:22:00+00:00" xsi:type='incident:IncidentType'>
                <incident:Title>MISP-STIX-Converter test event</incident:Title>
                <incident:Time>
                    <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
                    <incident:Incident_Reported precision="second">2020-10-25T16:22:00+00:00</incident:Incident_Reported>
                </incident:Time>
                <incident:Reporter>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Reporter>
                <incident:Information_Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Information_Source>
            </stix:Incident>
        </stix:Incidents>
    </stix:STIX_Package>
    ```

We can already see the published timestamp is exported as well when the event is published.  
Now we can have a look at the results when we add attributes, objects, galaxies, or tags (**TLinks to the detailed mappings for each structure type are available below**).

Exporting tags is pretty much straight forward and does not require a complex mapping:
- Event with tags
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
    ```xml
    <stix:STIX_Package id="MISP:STIXPackage-91b18402-618a-4818-8432-4ab41ec8b890" version="1.1.1" timestamp="2020-10-25T16:22:00+00:00">
        <stix:STIX_Header>
            <stix:Title>Export from MISP MISP</stix:Title>
        </stix:STIX_Header>
        <stix:Incidents>
            <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T16:22:00+00:00" xsi:type='incident:IncidentType'>
                <incident:Title>MISP-STIX-Converter test event</incident:Title>
                <incident:Time>
                    <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
                </incident:Time>
                <incident:Reporter>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Reporter>
                <incident:Information_Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Information_Source>
                <incident:Handling>
                    <marking:Marking>
                        <marking:Marking_Structure xsi:type='tlpMarking:TLPMarkingStructureType' color="WHITE"/>
                        <marking:Marking_Structure xsi:type='simpleMarking:SimpleMarkingStructureType'>
                            <simpleMarking:Statement>misp:tool="misp2stix"</simpleMarking:Statement>
                        </marking:Marking_Structure>
                        <marking:Marking_Structure xsi:type='simpleMarking:SimpleMarkingStructureType'>
                            <simpleMarking:Statement>misp-galaxy:mitre-attack-pattern="Code Signing - T1116"</simpleMarking:Statement>
                        </marking:Marking_Structure>
                        <marking:Marking_Structure xsi:type='simpleMarking:SimpleMarkingStructureType'>
                            <simpleMarking:Statement>misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"</simpleMarking:Statement>
                        </marking:Marking_Structure>
                    </marking:Marking>
                </incident:Handling>
            </stix:Incident>
        </stix:Incidents>
    </stix:STIX_Package>
    ```

As shown with this example, tags are basically exported as is in a list of marking structures, depending whether they are TLP marking or not.

If you are familiar with the MISP format, you can already see there are some tags representing MISP galaxies, because galaxies are referenced in the tags where their definition is embedded within the `Galaxy` field.  
With the next example we will see that every galaxy actually included in the event and referenced within the tags exported as any galaxy (detailed mapping available below) and not longer exported in the markings list:  
`misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"` is the tag name for the mitre-attack-pattern galaxy `Access Token Manipulation - T1134` and is in the list of tags, but exported as a galaxy since it is included in the galaxies, but `misp-galaxy:mitre-attack-pattern="Code Signing - T1116"` is only a tag.
- Event with galaxy
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
    ```xml
    <stix:STIX_Package id="MISP:STIXPackage-91b18402-618a-4818-8432-4ab41ec8b890" version="1.1.1" timestamp="2020-10-25T16:22:00+00:00">
        <stix:STIX_Header>
            <stix:Title>Export from MISP MISP</stix:Title>
        </stix:STIX_Header>
        <stix:TTPs>
            <stix:TTP id="MISP:TTP-dcaa092b-7de9-4a21-977f-7fcb77e89c48" timestamp="2020-10-25T16:22:00.763108+00:00" xsi:type='ttp:TTPType'>
                <ttp:Title>Attack Pattern (MISP Galaxy)</ttp:Title>
                <ttp:Behavior>
                    <ttp:Attack_Patterns>
                        <ttp:Attack_Pattern capec_id="CAPEC-633" id="MISP:AttackPattern-dcaa092b-7de9-4a21-977f-7fcb77e89c48">
                            <ttp:Title>Access Token Manipulation - T1134</ttp:Title>
                            <ttp:Description>Windows uses access tokens to determine the ownership of a running process.</ttp:Description>
                        </ttp:Attack_Pattern>
                    </ttp:Attack_Patterns>
                </ttp:Behavior>
            </stix:TTP>
        </stix:TTPs>
        <stix:Incidents>
            <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T16:22:00+00:00" xsi:type='incident:IncidentType'>
                <incident:Title>MISP-STIX-Converter test event</incident:Title>
                <incident:Time>
                    <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
                </incident:Time>
                <incident:Reporter>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Reporter>
                <incident:Leveraged_TTPs>
                    <incident:Leveraged_TTP>
                        <stixCommon:Relationship>Attack Pattern</stixCommon:Relationship>
                        <stixCommon:TTP idref="MISP:TTP-dcaa092b-7de9-4a21-977f-7fcb77e89c48" xsi:type='ttp:TTPType'/>
                    </incident:Leveraged_TTP>
                </incident:Leveraged_TTPs>
                <incident:Information_Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>MISP</stixCommon:Name>
                    </stixCommon:Identity>
                </incident:Information_Source>
                <incident:Handling>
                    <marking:Marking>
                        <marking:Marking_Structure xsi:type='simpleMarking:SimpleMarkingStructureType'>
                            <simpleMarking:Statement>misp-galaxy:mitre-attack-pattern="Code Signing - T1116"</simpleMarking:Statement>
                        </marking:Marking_Structure>
                    </marking:Marking>
                </incident:Handling>
            </stix:Incident>
        </stix:Incidents>
    </stix:STIX_Package>
    ```

We can see in this case the Galaxy is exported as `TTP` and is then in the list of TTPs, where its reference is in the list of `Leveraged TTPs` within the `Incident`.  
The principle remains the same if the Galaxy would have been a `Threat Actor` or a `Course of Action`: the data itself is embedded within the list of (respectively) Threat Actors or Courses of Action, and their reference is in the list of (respectively) `Attributed Threat Actors` or `COA Taken`

We will now focus on the data contained in the `Incident` because the `STIX Package` is going to remain the same, **keep in mind it is not skipped or removed, we just simplify here the examples display**

Exporting attributes differs from exporting objects in terms of complexity of the parsing, but both result in the creation of `Indicators` or `Observable` in most cases. The parameter that triggers one or the other case is simply the `to_ids` flag:
- Event with attribute(s) or object(s) producing indicator(s)
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
                    "type": "ip-src",
                    "category": "Network activity",
                    "value": "1.2.3.4",
                    "timestamp": "1605723614",
                    "comment": "Source IP test attribute",
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
    ```xml
    <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T18:20:13+00:00" xsi:type='incident:IncidentType'>
        <incident:Title>MISP-STIX-Converter test event</incident:Title>
        <incident:Time>
            <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
        </incident:Time>
        <incident:Reporter>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </incident:Reporter>
        <incident:Related_Indicators>
            <incident:Related_Indicator>
                <stixCommon:Relationship>Network activity</stixCommon:Relationship>
                <stixCommon:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
                    <indicator:Title>Network activity: 1.2.3.4 (MISP Attribute)</indicator:Title>
                    <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
                    <indicator:Description>Source IP test attribute</indicator:Description>
                    <indicator:Valid_Time_Position/>
                    <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Object id="MISP:Address-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                            <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="true" is_destination="false">
                                <AddressObj:Address_Value condition="Equals">1.2.3.4</AddressObj:Address_Value>
                            </cybox:Properties>
                        </cybox:Object>
                    </indicator:Observable>
                    <indicator:Confidence timestamp="2020-10-25T16:22:00+00:00">
                        <stixCommon:Value>High</stixCommon:Value>
                        <stixCommon:Description>Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none</stixCommon:Description>
                    </indicator:Confidence>
                    <indicator:Producer>
                        <stixCommon:Identity>
                            <stixCommon:Name>MISP</stixCommon:Name>
                        </stixCommon:Identity>
                    </indicator:Producer>
                </stixCommon:Indicator>
            </incident:Related_Indicator>
        </incident:Related_Indicators>
        <incident:Information_Source>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </incident:Information_Source>
    </stix:Incident>
    ```

- Event with attribute(s) or object(s) producing observable(s)
  - MISP
    ```json
    {
        "Event": {
            "uuid": "91b18402-618a-4818-8432-4ab41ec8b890",
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
                    "type": "ip-src",
                    "category": "Network activity",
                    "value": "1.2.3.4",
                    "timestamp": "1605723614",
                    "comment": "Source IP test attribute",
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
    ```xml
    <stix:Incident id="MISP:Incident-91b18402-618a-4818-8432-4ab41ec8b890" timestamp="2020-10-25T16:22:00+00:00" xsi:type='incident:IncidentType'>
        <incident:Title>MISP-STIX-Converter test event</incident:Title>
        <incident:Time>
            <incident:Incident_Discovery precision="second">2020-10-25T00:00:00+00:00</incident:Incident_Discovery>
        </incident:Time>
        <incident:Reporter>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </incident:Reporter>
        <incident:Related_Observables>
            <incident:Related_Observable>
                <stixCommon:Relationship>Network activity</stixCommon:Relationship>
                <stixCommon:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Object id="MISP:Address-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="true" is_destination="false">
                            <AddressObj:Address_Value condition="Equals">1.2.3.4</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </stixCommon:Observable>
            </incident:Related_Observable>
        </incident:Related_Observables>
        <incident:Information_Source>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </incident:Information_Source>
    </stix:Incident>
    ```

Those two last examples were very simple to have an overview of what happens.

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Attributes export to STIX1 mapping](misp_attributes_to_stix1.md)
- [Objects export to STIX1 mapping](misp_objects_to_stix1.md)
- [Galaxies export to STIX1 mapping](misp_galaxies_to_stix1.md)

([Go back to the main documentation](README.md))
