# MISP Attributes to STIX1 mapping

MISP Attributes are the actual raw data used by analysts to describe the IoCs and observed data related to a specific event (which could be an actual threat report, an IP watchlist, etc.)  
Thus, in most of the cases, a MISP Attribute is exported to STIX as `Indicator` if its `to_ids` flag is set, or as `Observable` if its `to_ids` flag is false. But there are also some other examples where MISP attributes are exported neither as indicator nor as observable, this documentation gives all the details about the single attributes mapping into STIX objects, depending on the type of the attributes.

As we can see in the [detailed Events mapping documentation](misp_events_to_stix1.md), attributes within their event are exported in different STIX objects embedded in a `STIX Package`. Indicators and observables are also embedded in the `Incident` but it is not the case for TTPS for instance.  
So for the rest of this documentation, in order to keep the content clear enough and to skip the irrelevant part, we will consider the followings:
- Indicators and observables are displayed as standalone objects, but we keep in mind that **if the related MISP attributes are exported within their event, those STIX objects are actually exported within their Incident and STIX Package**
- We will give details about the context of each STIX object being neither an Indicator not an Observable case by case, since those ones are also displayed outside of their Incident or STIX package.
- In the following examples, every MISP attribute that has a `to_ids` flag, has the default value for this flag, depending on the attribute type.
- Switching the `to_ids` flag value would simply change the result from Indicator to Observable or from Observable to indicator
- More details given about the `to_ids` flag if necessary, case by case

### Current mapping

- AS
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "AS",
        "category": "Network activity",
        "value": "AS174",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:AutonomousSystem-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="ASObj:ASObjectType">
                <ASObj:Handle condition="Equals">AS174</ASObj:Handle>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- attachment
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "attachment",
        "category": "Payload delivery",
        "value": "attachment.test",
        "data": "ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Title>attachment.test</cybox:Title>
        <cybox:Object id="MISP:Artifact-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="ArtifactObj:ArtifactObjectType">
                <ArtifactObj:Raw_Artifact condition="Equals"><![CDATA[ZWNobyAiREFOR0VST1VTIE1BTFdBUkUiIAoK]]></ArtifactObj:Raw_Artifact>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- authentihash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "authentihash",
        "category": "Payload delivery",
        "value": "b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1",
        "timestamp": "1603642920",
        "comment": "authentihash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>authentihash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- campaign-name
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "campaign-name",
        "category": "Attribution",
        "value": "MartyMcFly",
        "comment": "campaign-name test attribute"
    }
    ```
  - STIX
    ```xml
    <campaign:Campaign id="MISP-Project:Campaign-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2021-06-03T11:01:56" xsi:type='campaign:CampaignType'>
        <campaign:Title>Attribution: MartyMcFly (MISP Attribute)</campaign:Title>
        <campaign:Description>campaign-name test attribute</campaign:Description>
        <campaign:Names>
            <campaign:Name>MartyMcFly</campaign:Name>
        </campaign:Names>
    </campaign:Campaign>
    ```

- cdhash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "cdhash",
        "category": "Payload delivery",
        "value": "68b01861f223a9ae2cc2a0688cef222a9730d468",
        "timestamp": "1603642920",
        "comment": "cdhash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 38b01861f223a9ae2cc2a0388cef222a9730d438 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>cdhash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">68b01861f223a9ae2cc2a0688cef222a9730d468</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- comment
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "comment",
        "category": "Other",
        "value": "Test comment"
    }
    ```
  - STIX
    ```xml
    <incident:HistoryItemType>
        <incident:Journal_Entry time_precision="second">Attribute (Other - comment): Test comment</incident:Journal_Entry>
    </incident:HistoryItemType>
    ```

- domain
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "domain",
        "category": "Network activity",
        "value": "circl.lu",
        "timestamp": "1603642920",
        "comment": "Domain test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: circl.lu (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
        <indicator:Description>Domain test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:DomainName-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
                    <DomainNameObj:Value condition="Equals">circl.lu</DomainNameObj:Value>
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
    </indicator:Indicator>
    ```

- domain|ip
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "domain|ip",
        "category": "Network activity",
        "value": "circl.lu|149.13.33.14",
        "timestamp": "1603642920",
        "comment": "Domain|ip test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: circl.lu|149.13.33.14 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
        <indicator:Description>Domain|ip test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:ObservableComposition-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Observable_Composition operator="AND">
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
     <cybox:Object id="MISP:DomainName-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
                            <DomainNameObj:Value condition="Equals">circl.lu</DomainNameObj:Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Object id="MISP:Address-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">149.13.33.14</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </cybox:Observable_Composition>
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
    </indicator:Indicator>
    ```

- email-attachment
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-attachment",
        "category": "Payload delivery",
        "value": "email_attachment.test",
        "timestamp": "1603642920",
        "comment": "Email attachment test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: email_attachment.test (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malicious E-mail</indicator:Type>
        <indicator:Description>Email attachment test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:EmailMessage-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                    <EmailMessageObj:Attachments>
                        <EmailMessageObj:File object_reference="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f"/>
                    </EmailMessageObj:Attachments>
                </cybox:Properties>
                <cybox:Related_Objects>
                    <cybox:Related_Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="FileObj:FileObjectType">
                            <FileObj:File_Name condition="Equals">email_attachment.test</FileObj:File_Name>
                        </cybox:Properties>
                        <cybox:Relationship xsi:type="cyboxVocabs:ObjectRelationshipVocab-1.1">Contains</cybox:Relationship>
      </cybox:Related_Object>
                </cybox:Related_Objects>
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
    </indicator:Indicator>
    ```

- email-body
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-body",
        "category": "Payload delivery",
        "value": "Email body test",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:EmailMessage-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Raw_Body condition="Equals"><![CDATA[Email bodytest]]></EmailMessageObj:Raw_Body>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- email-dst
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "email-dst",
        "category": "Payload delivery",
        "value": "dst@email.test",
        "timestamp": "1603642920",
        "comment": "Destination email address test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: dst@email.test (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malicious E-mail</indicator:Type>
        <indicator:Description>Destination email address test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Object id="MISP:EmailMessage-518b4bcb-a86b-4783-9457-391d548b605b">
                <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                    <EmailMessageObj:Header>
                        <EmailMessageObj:To>
                            <EmailMessageObj:Recipient xsi:type="AddressObj:AddressObjectType" category="e-mail">
                                <AddressObj:Address_Value>dst@email.test</AddressObj:Address_Value>
                            </EmailMessageObj:Recipient>
           </EmailMessageObj:To>
                    </EmailMessageObj:Header>
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
    </indicator:Indicator>
    ```

- email-header
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-header",
        "category": "Payload delivery",
        "value": "from mail.example.com ([198.51.100.3]) by smtp.gmail.com",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:EmailMessage-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Raw_Header condition="Equals"><![CDATA[from mail.example.com ([198.51.100.3]) by smtp.gmail.com]]></EmailMessageObj:Raw_Header>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- email-message-id
  - MISP
    ```json
    {
        "uuid": "f3745b11-2b82-4798-80ba-d32c506135ec",
        "type": "email-message-id",
        "category": "Payload delivery",
        "value": "1234",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-f3745b11-2b82-4798-80ba-d32c506135ec">
        <cybox:Object id="MISP-Project:EmailMessage-f3745b11-2b82-4798-80ba-d32c506135ec">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Header>
                    <EmailMessageObj:Message_ID condition="Equals">1234</EmailMessageObj:Message_ID>
                </EmailMessageObj:Header>
            </cybox:Properties>
        </cybox:Object>
  </cybox:ObservableType>
    ```

- email-mime-boundary
  - MISP
    ```json
    {
        "uuid": "30c728ce-4ee4-4dc4-b7f6-ae4e900f4aa9",
        "type": "email-mime-boundary",
        "category": "Payload delivery",
        "value": "----=_NextPart_001_1F9B_01D27892.CB6A37E0",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-30c728ce-4ee4-4dc4-b7f6-ae4e900f4aa9">
        <cybox:Object id="MISP-Project:EmailMessage-30c728ce-4ee4-4dc4-b7f6-ae4e900f4aa9">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Header>
                    <EmailMessageObj:Boundary condition="Equals">----=_NextPart_001_1F9B_01D27892.CB6A37E0</EmailMessageObj:Boundary>
                </EmailMessageObj:Header>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- email-reply-to
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "email-reply-to",
        "category": "Payload delivery",
        "value": "reply-to@email.test",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
        <cybox:Object id="MISP:EmailMessage-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Header>
                    <EmailMessageObj:Reply_To xsi:type="AddressObj:AddressObjectType" category="e-mail">
                        <AddressObj:Address_Value condition="Equals">reply-to@email.test</AddressObj:Address_Value>
                    </EmailMessageObj:Reply_To>
                </EmailMessageObj:Header>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- email-src
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "email-src",
        "category": "Payload delivery",
        "value": "src@email.test",
        "timestamp": "1603642920",
        "comment": "Source email address test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: src@email.test (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malicious E-mail</indicator:Type>
        <indicator:Description>Source email address test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:EmailMessage-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                   <EmailMessageObj:Header>
                        <EmailMessageObj:From xsi:type="AddressObj:AddressObjectType" category="e-mail">
                            <AddressObj:Address_Value condition="Equals">src@email.test</AddressObj:Address_Value>
                        </EmailMessageObj:From>
                    </EmailMessageObj:Header>
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
    </indicator:Indicator>
    ```

- email-subject
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "email-subject",
        "category": "Payload delivery",
        "value": "Test Subject",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
        <cybox:Object id="MISP:EmailMessage-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Header>
                    <EmailMessageObj:Subject condition="Equals">Test Subject</EmailMessageObj:Subject>
                </EmailMessageObj:Header>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- email-x-mailer
  - MISP
    ```json
    {
        "uuid": "f09d8496-e2ba-4250-878a-bec9b85c7e96",
        "type": "email-x-mailer",
        "category": "Payload delivery",
        "value": "Email X-Mailer test",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-f09d8496-e2ba-4250-878a-bec9b85c7e96">
        <cybox:Object id="MISP-Project:EmailMessage-f09d8496-e2ba-4250-878a-bec9b85c7e96">
            <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                <EmailMessageObj:Header>
                    <EmailMessageObj:X_Mailer condition="Equals">Email X-Mailer test</EmailMessageObj:X_Mailer>
                </EmailMessageObj:Header>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- filename
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename",
        "category": "Payload delivery",
        "value": "test_file_name",
        "timestamp": "1603642920",
        "comment": "Filename test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>Filename test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
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
    </indicator:Indicator>
    ```

- filename|authentihash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|authentihash",
        "category": "Payload delivery",
        "value": "test_file_name|b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1",
        "timestamp": "1603642920",
        "comment": "filename|authentihash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|authentihash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">b2e12a5c44e7e01965c971de559933cb95d64bbac245531fe7d057610b49b6c1</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|impfuzzy
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|impfuzzy",
        "category": "Payload delivery",
        "value": "putty.exe|96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD",
        "timestamp": "1603642920",
        "comment": "filename|impfuzzy test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: putty.exe|96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|impfuzzy test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">putty.exe</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|imphash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|imphash",
        "category": "Payload delivery",
        "value": "test_file_name|a310eaa686fb53b40a6bebdee4cffc98",
        "timestamp": "1603642920",
        "comment": "filename|imphash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|a310eaa686fb53b40a6bebdee4cffc98 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|imphash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">a310eaa686fb53b40a6bebdee4cffc98</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|md5",
        "category": "Payload delivery",
        "value": "test_file_name|b2a5abfeef9e36964281a31e17b57c97",
        "timestamp": "1603642920",
        "comment": "filename|md5 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|b2a5abfeef9e36964281a31e17b57c97 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|md5 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">b2a5abfeef9e36964281a31e17b57c97</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|pehash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|pehash",
        "category": "Payload delivery",
        "value": "test_file_name|aad3abd1afba000356bbc35a20351b2ab466bc8c",
        "timestamp": "1603642920",
        "comment": "filename|pehash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|aad3abd1afba000356bbc35a20351b2ab466bc8c (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|pehash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">aad3abd1afba000356bbc35a20351b2ab466bc8c</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha1
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha1",
        "category": "Payload delivery",
        "value": "test_file_name|46aba99aa7158e4609aaa72b50990842fd22ae86",
        "timestamp": "1603642920",
        "comment": "filename|sha1 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|46aba99aa7158e4609aaa72b50990842fd22ae86 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha1 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">46aba99aa7158e4609aaa72b50990842fd22ae86</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha224",
        "category": "Payload delivery",
        "value": "test_file_name|5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9",
        "timestamp": "1603642920",
        "comment": "filename|sha224 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha224 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA224</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha256",
        "category": "Payload delivery",
        "value": "test_file_name|ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "filename|sha256 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha256 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha384
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha384",
        "category": "Payload delivery",
        "value": "test_file_name|302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3",
        "timestamp": "1603642920",
        "comment": "filename|sha384 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha384 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA384</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha512
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha512",
        "category": "Payload delivery",
        "value": "test_file_name|06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5",
        "timestamp": "1603642920",
        "comment": "filename|sha512 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha512 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA512</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha512/224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha512/224",
        "category": "Payload delivery",
        "value": "test_file_name|2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc",
        "timestamp": "1603642920",
        "comment": "filename|sha512/224 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha512/224 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA224</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|sha512/256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|sha512/256",
        "category": "Payload delivery",
        "value": "test_file_name|3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213",
        "timestamp": "1603642920",
        "comment": "filename|sha512/256 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|sha512/256 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|ssdeep
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|ssdeep",
        "category": "Payload delivery",
        "value": "test_file_name|3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK",
        "timestamp": "1603642920",
        "comment": "filename|ssdeep test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|ssdeep test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SSDEEP</cyboxCommon:Type>
                            <cyboxCommon:Fuzzy_Hash_Value>3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK</cyboxCommon:Fuzzy_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|tlsh
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|tlsh",
        "category": "Payload delivery",
        "value": "test_file_name|5b73df03d9a5fb42c11952fc3d570de6aa5f2358618897eb20e18e2fad611b34ecf14d",
        "timestamp": "1603642920",
        "comment": "filename|tlsh test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|5b73df03d9a5fb42c11952fc3d570de6aa5f2358618897eb20e18e2fad611b34ecf14d (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|tlsh test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">5b73df03d9a5fb42c11952fc3d570de6aa5f2358618897eb20e18e2fad611b34ecf14d</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- filename|vhash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "filename|vhash",
        "category": "Payload delivery",
        "value": "test_file_name|83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b",
        "timestamp": "1603642920",
        "comment": "filename|vhash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: test_file_name|83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>filename|vhash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- hostname
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "hostname",
        "category": "Network activity",
        "value": "circl.lu",
        "timestamp": "1603642920",
        "comment": "Hostname test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: circl.lu (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
        <indicator:Description>Hostname test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:Hostname-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="HostnameObj:HostnameObjectType">
                    <HostnameObj:Hostname_Value condition="Equals">circl.lu</HostnameObj:Hostname_Value>
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
    </indicator:Indicator>
    ```

- hostname|port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "hostname|port",
        "category": "Network activity",
        "value": "circl.lu|8443",
        "timestamp": "1603642920",
        "comment": "Hostname|port test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: circl.lu|8443 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Hostname|port test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:SocketAddress-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="SocketAddressObj:SocketAddressObjectType">
                    <SocketAddressObj:Hostname xsi:type="HostnameObj:HostnameObjectType">
                        <HostnameObj:Hostname_Value condition="Equals">circl.lu</HostnameObj:Hostname_Value>
                    </SocketAddressObj:Hostname>
                    <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                        <PortObj:Port_Value condition="Equals">8443</PortObj:Port_Value>
                    </SocketAddressObj:Port>
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
    </indicator:Indicator>
    ```

- http-method
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "http-method",
        "category": "Network activity",
        "value": "POST",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:HTTPSession-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Client_Request>
                        <HTTPSessionObj:HTTP_Request_Line>
                            <HTTPSessionObj:HTTP_Method condition="Equals">POST</HTTPSessionObj:HTTP_Method>
                        </HTTPSessionObj:HTTP_Request_Line>
                    </HTTPSessionObj:HTTP_Client_Request>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- impfuzzy
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "impfuzzy",
        "category": "Payload delivery",
        "value": "96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD",
        "timestamp": "1603642920",
        "comment": "impfuzzy test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>impfuzzy test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">96:oO0b1atxHn63OxfUvDaSf5tKN2Sm68BXTCljAwhmapACiONvR83sn:oO41atxHn63OxfUvDaSfvJ52ljD</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- imphash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "imphash",
        "category": "Payload delivery",
        "value": "a310eaa686fb53b40a6bebdee4cffc98",
        "timestamp": "1603642920",
        "comment": "imphash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: a310eaa686fb53b40a6bebdee4cffc98 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>imphash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">a310eaa686fb53b40a6bebdee4cffc98</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- ip-dst
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "ip-dst",
        "category": "Network activity",
        "value": "5.6.7.8",
        "timestamp": "1603642920",
        "comment": "Destination IP test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: 5.6.7.8 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
        <indicator:Description>Destination IP test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Object id="MISP:Address-518b4bcb-a86b-4783-9457-391d548b605b">
                <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                    <AddressObj:Address_Value condition="Equals">5.6.7.8</AddressObj:Address_Value>
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
    </indicator:Indicator>
    ```

- ip-dst|port
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "ip-dst|port",
        "category": "Network activity",
        "value": "5.6.7.8|5678",
        "timestamp": "1603642920",
        "comment": "Destination IP | Port test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: 5.6.7.8|5678 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
        <indicator:Description>Destination IP | Port test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Object id="MISP:SocketAddress-518b4bcb-a86b-4783-9457-391d548b605b">
                <cybox:Properties xsi:type="SocketAddressObj:SocketAddressObjectType">
                    <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                        <AddressObj:Address_Value condition="Equals">5.6.7.8</AddressObj:Address_Value>
                    </SocketAddressObj:IP_Address>
                    <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                        <PortObj:Port_Value condition="Equals">5678</PortObj:Port_Value>
                    </SocketAddressObj:Port>
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
    </indicator:Indicator>
    ```

- ip-src
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "ip-src",
        "category": "Network activity",
        "value": "1.2.3.4",
        "timestamp": "1603642920",
        "comment": "Source IP test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
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
    </indicator:Indicator>
    ```

- ip-src|port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "ip-src|port",
        "category": "Network activity",
        "value": "1.2.3.4|1234",
        "timestamp": "1603642920",
        "comment": "Source IP | Port test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: 1.2.3.4|1234 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
        <indicator:Description>Source IP | Port test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:SocketAddress-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="SocketAddressObj:SocketAddressObjectType">
                    <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="true" is_destination="false">
                        <AddressObj:Address_Value condition="Equals">1.2.3.4</AddressObj:Address_Value>
                    </SocketAddressObj:IP_Address>
                    <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                        <PortObj:Port_Value condition="Equals">1234</PortObj:Port_Value>
                    </SocketAddressObj:Port>
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
    </indicator:Indicator>
    ```

- link
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "link",
        "category": "Network activity",
        "value": "https://github.com/MISP/MISP",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:URI-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
       <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                <URIObj:Value condition="Equals">https://github.com/MISP/MISP</URIObj:Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- mac-address
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "mac-address",
        "category": "Payload delivery",
        "value": "12:34:56:78:90:AB",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:System-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="SystemObj:SystemObjectType">
                <SystemObj:Network_Interface_List>
                    <SystemObj:Network_Interface>
                        <SystemObj:MAC>12:34:56:78:90:AB</SystemObj:MAC>
                    </SystemObj:Network_Interface>
                </SystemObj:Network_Interface_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- malware-sample
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "malware-sample",
        "category": "Payload delivery",
        "value": "oui|8764605c6f388c89096b534d33565802",
        "data": "UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==",
        "timestamp": "1603642920",
        "comment": "Malware Sample test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: oui|8764605c6f388c89096b534d33565802 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Malware Sample test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Title>oui</cybox:Title>
            <cybox:Object id="MISP:Artifact-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="ArtifactObj:ArtifactObjectType">
                    <ArtifactObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">8764605c6f388c89096b534d33565802</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </ArtifactObj:Hashes>
                    <ArtifactObj:Raw_Artifact condition="Equals"><![CDATA[UEsDBAoACQAAAAaOU1EvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAAzu1jV87tY1fdXgLAAEEIQAAAAQhAAAAUxIrDdj2V8dHuHoKPVDwAeOqqY3shFf5CKvJ/TZg7iNXlXSgxTaWwMnb6fESF/RQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAAaOU1FAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAM7tY1fO7WNX3V4CwABBCEAAAAEIQAAAI7lFn9K1EsuznCkFF9PRFBLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAAAGjlNRL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAAzu1jV91eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAAAGjlNRQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAM7tY1fdXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==]]></ArtifactObj:Raw_Artifact>
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
    </indicator:Indicator>
    ```

- md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "md5",
        "category": "Payload delivery",
        "value": "b2a5abfeef9e36964281a31e17b57c97",
        "timestamp": "1603642920",
        "comment": "MD5 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: b2a5abfeef9e36964281a31e17b57c97 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>MD5 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">b2a5abfeef9e36964281a31e17b57c97</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- mutex
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "mutex",
        "category": "Artifacts dropped",
        "value": "MutexTest",
        "timestamp": "1603642920",
        "comment": "Mutex test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Artifacts dropped: MutexTest (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Host Characteristics</indicator:Type>
        <indicator:Description>Mutex test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:Mutex-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="MutexObj:MutexObjectType">
                    <MutexObj:Name condition="Equals">MutexTest</MutexObj:Name>
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
    </indicator:Indicator>
    ```

- named pipe
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "named pipe",
        "category": "Artifacts dropped",
        "value": "\\.\\pipe\\testpipe",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:Pipe-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="PipeObj:PipeObjectType" named="true">
                <PipeObj:Name condition="Equals">\.\pipe	estpipe</PipeObj:Name>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- other
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "other",
        "category": "Other",
        "value": "Test undefined attribute"
    }
    ```
  - STIX
    ```xml
    <incident:HistoryItemType>
        <incident:Journal_Entry time_precision="second">Attribute (Other - other): Test undefined attribute</incident:Journal_Entry>
    </incident:HistoryItemType>
    ```

- pattern-in-file
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "pattern-in-file",
        "category": "Artifacts dropped",
        "value": "P4tt3rn_1n_f1l3_t3st",
        "timestamp": "1603642920",
        "comment": "Named pipe test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Artifacts dropped: P4tt3rn_1n_f1l3_t3st (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Named pipe test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Byte_Runs>
                        <cyboxCommon:Byte_Run>
                            <cyboxCommon:Byte_Run_Data>P4tt3rn_1n_f1l3_t3st</cyboxCommon:Byte_Run_Data>
                        </cyboxCommon:Byte_Run>
                    </FileObj:Byte_Runs>
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
    </indicator:Indicator>
    ```

- pehash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "pehash",
        "category": "Payload delivery",
        "value": "aad3abd1afba000356bbc35a20351b2ab466bc8c",
        "timestamp": "1603642920",
        "comment": "pehash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: aad3abd1afba000356bbc35a20351b2ab466bc8c (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>pehash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">aad3abd1afba000356bbc35a20351b2ab466bc8c</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- port
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "port",
        "category": "Network activity",
        "value": "8443",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:Port-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="PortObj:PortObjectType">
                <PortObj:Port_Value condition="Equals">8443</PortObj:Port_Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- regkey
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "regkey",
        "category": "Persistence mechanism",
        "value": "HKLM\\Software\\mthjk",
        "timestamp": "1603642920",
        "comment": "Regkey test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Persistence mechanism: HKLM\Software\mthjk (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Host Characteristics</indicator:Type>
        <indicator:Description>Regkey test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:WinRegistryKey-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                    <WinRegistryKeyObj:Key condition="Equals">HKLM\Software\mthjk</WinRegistryKeyObj:Key>
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
    </indicator:Indicator>
    ```

- regkey|value
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "regkey|value",
        "category": "Persistence mechanism",
        "value": "HKLM\\Software\\mthjk|1234567890",
        "timestamp": "1603642920",
        "comment": "Regkey | value test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Persistence mechanism: HKLM\Software\mthjk|1234567890 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Host Characteristics</indicator:Type>
        <indicator:Description>Regkey | value test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:WinRegistryKey-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                    <WinRegistryKeyObj:Key condition="Equals">HKLM\Software\mthjk</WinRegistryKeyObj:Key>
                    <WinRegistryKeyObj:Values>
                        <WinRegistryKeyObj:Value>
                            <WinRegistryKeyObj:Data condition="Equals">1234567890</WinRegistryKeyObj:Data>
                        </WinRegistryKeyObj:Value>
                    </WinRegistryKeyObj:Values>
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
    </indicator:Indicator>
    ```

- sha1
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha1",
        "category": "Payload delivery",
        "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
        "timestamp": "1603642920",
        "comment": "sha1 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 46aba99aa7158e4609aaa72b50990842fd22ae86 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha1 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">46aba99aa7158e4609aaa72b50990842fd22ae86</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha224",
        "category": "Payload delivery",
        "value": "5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9",
        "timestamp": "1603642920",
        "comment": "sha224 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha224 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA224</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">5d6dc524ce96b1bb5e96d8dc116ff53b457ffb7f16afd9019a0dd8e9</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha256",
        "category": "Payload delivery",
        "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "sha256 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha256 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha384
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha384",
        "category": "Payload delivery",
        "value": "302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3",
        "timestamp": "1603642920",
        "comment": "sha384 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha384 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA384</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">302d83d92882003081448357ba1ebbfc5528f7c164b615e7a5c532eb6209f35eb05c442460222236a13732a28aa0f4d3</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha512
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha512",
        "category": "Payload delivery",
        "value": "06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5",
        "timestamp": "1603642920",
        "comment": "sha512 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha512 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA512</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">06f531e49154d59f684475da95693df1fccd50b505e6d3ca028c9d84fcfc79ef287704dd0b24b022bfac6ba9ee581d19f440773dd00cfcfecf068b644ecbecb5</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha512/224
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha512/224",
        "category": "Payload delivery",
        "value": "2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc",
        "timestamp": "1603642920",
        "comment": "sha512/224 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha512/224 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA224</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">2874893927788197307efb678d9462ea3cb7680b0826a9ff69e2fafc</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- sha512/256
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "sha512/256",
        "category": "Payload delivery",
        "value": "3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213",
        "timestamp": "1603642920",
        "comment": "sha512/256 test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>sha512/256 test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">3c74fe8c148812a0b5606aa19a81c98f30ec761f12924115ed8e02eb2f2e3213</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- size-in-bytes
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "size-in-bytes",
        "category": "Other",
        "value": "1234",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:Size_In_Bytes condition="Equals">1234</FileObj:Size_In_Bytes>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- snort
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "snort",
        "category": "Network activity",
        "value": "alert tcp any any -> any any (msg:\"oui\")",
        "timestamp": "1603642920",
        "comment": "Snort test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <!--To_ids flag must be true since Observables have no Test_mechanisms field-->
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: alert tcp any any -&gt; any any (msg:"oui") (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Snort test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Test_Mechanisms>
            <indicator:Test_Mechanism xsi:type='snortTM:SnortTestMechanismType'>
                <snortTM:Rule><![CDATA[{'value': 'alert tcp any any -> any any (msg:"oui")', 'encoded': True}]]></snortTM:Rule>
            </indicator:Test_Mechanism>
        </indicator:Test_Mechanisms>
        <indicator:Confidence timestamp="2020-10-25T16:22:00+00:00">
            <stixCommon:Value>High</stixCommon:Value>
            <stixCommon:Description>Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none</stixCommon:Description>
        </indicator:Confidence>
        <indicator:Producer>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </indicator:Producer>
    </indicator:Indicator>
    ```

- ssdeep
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "ssdeep",
        "category": "Payload delivery",
        "value": "3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK",
        "timestamp": "1603642920",
        "comment": "ssdeep test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>ssdeep test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SSDEEP</cyboxCommon:Type>
                            <cyboxCommon:Fuzzy_Hash_Value>3072:WsyjTzEvLFOL8AqCiueLt1VFu9+zcSywy0mcj90nSJ5NatCmtWwNQLK:W/zEvLFOLdq9uebdSwHN9n5wtkwNwK</cyboxCommon:Fuzzy_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- target-email
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "target-email",
        "value": "target@email.test",
        "category": "Targeting data"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Victim id="MISP:Identity-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
        <stix-ciqidentity:CIQIdentity3.0InstanceType id="MISP:Identity-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
            <stixCommon:Name>Targeting data: target@email.test (MISP Attribute)</stixCommon:Name>
            <stix-ciqidentity:Specification xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
          <xpil:ElectronicAddressIdentifiers xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
            <xpil:ElectronicAddressIdentifier>target@email.test</xpil:ElectronicAddressIdentifier>
          </xpil:ElectronicAddressIdentifiers>
        </stix-ciqidentity:Specification>
        </stix-ciqidentity:CIQIdentity3.0InstanceType>
    </incident:Victim>
    ```

- target-external
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "target-external",
        "value": "external.target",
        "category": "Targeting data"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Victim id="MISP:Identity-518b4bcb-a86b-4783-9457-391d548b605b" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
        <stix-ciqidentity:CIQIdentity3.0InstanceType id="MISP:Identity-518b4bcb-a86b-4783-9457-391d548b605b" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
            <stixCommon:Name>Targeting data: external.target (MISP Attribute)</stixCommon:Name>
            <stix-ciqidentity:Specification xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
          <xpil:PartyName xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
            <xnl:NameLine xmlns:xnl="urn:oasis:names:tc:ciq:xnl:3">External target: external.target</xnl:NameLine>
          </xpil:PartyName>
        </stix-ciqidentity:Specification>
        </stix-ciqidentity:CIQIdentity3.0InstanceType>
    </incident:Victim>
    ```

- target-location
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "target-location",
        "value": "Luxembourg",
        "category": "Targeting data"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Victim id="MISP:Identity-34cb1a7c-55ec-412a-8684-ba4a88d83a45" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
        <stix-ciqidentity:CIQIdentity3.0InstanceType id="MISP:Identity-34cb1a7c-55ec-412a-8684-ba4a88d83a45" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
            <stixCommon:Name>Targeting data: Luxembourg (MISP Attribute)</stixCommon:Name>
            <stix-ciqidentity:Specification xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
          <xpil:Addresses xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
            <xpil:Address>
              <xal:FreeTextAddress xmlns:xal="urn:oasis:names:tc:ciq:xal:3">
                <xal:AddressLine>Luxembourg</xal:AddressLine>
              </xal:FreeTextAddress>
            </xpil:Address>
          </xpil:Addresses>
        </stix-ciqidentity:Specification>
        </stix-ciqidentity:CIQIdentity3.0InstanceType>
    </incident:Victim>
    ```

- target-machine
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "target-machine",
        "value": "target.machine",
        "comment": "Target machine test attribute"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Affected_Assets>
        <incident:Affected_Asset>
            <incident:Description>target.machine (Target machine test attribute)</incident:Description>
        </incident:Affected_Asset>
    </incident:Affected_Assets>
    ```

- target-org
  - MISP
    ```json
    {
        "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
        "type": "target-org",
        "value": "Blizzard",
        "category": "Targeting data"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Victim id="MISP:Identity-f2259650-bc33-4b64-a3a8-a324aa7ea6bb" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
        <stix-ciqidentity:CIQIdentity3.0InstanceType id="MISP:Identity-f2259650-bc33-4b64-a3a8-a324aa7ea6bb" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
            <stixCommon:Name>Targeting data: Blizzard (MISP Attribute)</stixCommon:Name>
            <stix-ciqidentity:Specification xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
          <xpil:PartyName xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
            <xnl:OrganisationName xmlns:xnl="urn:oasis:names:tc:ciq:xnl:3">
              <xnl:NameElement>Blizzard</xnl:NameElement>
            </xnl:OrganisationName>
          </xpil:PartyName>
        </stix-ciqidentity:Specification>
        </stix-ciqidentity:CIQIdentity3.0InstanceType>
    </incident:Victim>
    ```

- target-user
  - MISP
    ```json
    {
        "uuid": "90bd7dae-b78c-4025-9073-568950c780fb",
        "type": "target-user",
        "value": "iglocska",
        "category": "Targeting data"
    }
    ```
  - STIX
    ```xml
    <!--Embedded within the Incident's field named Victims-->
    <incident:Victim id="MISP:Identity-90bd7dae-b78c-4025-9073-568950c780fb" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
        <stix-ciqidentity:CIQIdentity3.0InstanceType id="MISP:Identity-90bd7dae-b78c-4025-9073-568950c780fb" xsi:type="stix-ciqidentity:CIQIdentity3.0InstanceType">
            <stixCommon:Name>Targeting data: iglocska (MISP Attribute)</stixCommon:Name>
            <stix-ciqidentity:Specification xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
          <xpil:PartyName xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
            <xnl:PersonName xmlns:xnl="urn:oasis:names:tc:ciq:xnl:3">
              <xnl:NameElement>iglocska</xnl:NameElement>
            </xnl:PersonName>
          </xpil:PartyName>
        </stix-ciqidentity:Specification>
        </stix-ciqidentity:CIQIdentity3.0InstanceType>
    </incident:Victim>
    ```

- text
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "text",
        "category": "Other",
        "value": "Test text"
    }
    ```
  - STIX
    ```xml
    <incident:HistoryItemType>
        <incident:Journal_Entry time_precision="second">Attribute (Other - text): Test text</incident:Journal_Entry>
    </incident:HistoryItemType>
    ```

- tlsh
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "tlsh",
        "category": "Payload delivery",
        "value": "1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
        "timestamp": "1603642920",
        "comment": "TLSH test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>TLSH test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Object id="MISP:File-518b4bcb-a86b-4783-9457-391d548b605b">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- uri
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "uri",
        "category": "Network activity",
        "value": "http://176.58.32.109/upd/51",
        "timestamp": "1603642920",
        "comment": "URI test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP-Project:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2021-06-03T12:50:21" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: http://176.58.32.109/upd/51 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>URI test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP-Project:URI-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                    <URIObj:Value condition="Equals">http://176.58.32.109/upd/51</URIObj:Value>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-06-03T12:50:21">
            <stixCommon:Value>High</stixCommon:Value>
<stixCommon:Description>Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none</stixCommon:Description>
        </indicator:Confidence>
        <indicator:Producer>
            <stixCommon:Identity>
                <stixCommon:Name>MISP-Project</stixCommon:Name>
            </stixCommon:Identity>
        </indicator:Producer>
    </indicator:Indicator>
    ```

- url
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "url",
        "category": "Network activity",
        "value": "https://misp-project.org/download/",
        "timestamp": "1603642920",
        "comment": "URL test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Network activity: https://misp-project.org/download/ (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
        <indicator:Description>URL test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:URI-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                    <URIObj:Value condition="Equals">https://misp-project.org/download/</URIObj:Value>
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
    </indicator:Indicator>
    ```

- user-agent
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "user-agent",
        "category": "Network activity",
        "value": "Mozilla Firefox",
        "timestamp": "1603642920",
        "comment": "User-agent test attribute",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
        <cybox:Object id="MISP:HTTPSession-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Client_Request>
                        <HTTPSessionObj:HTTP_Request_Header>
                            <HTTPSessionObj:Parsed_Header>
                                <HTTPSessionObj:User_Agent condition="Equals">Mozilla Firefox</HTTPSessionObj:User_Agent>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Request_Header>
                    </HTTPSessionObj:HTTP_Client_Request>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- vhash
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "vhash",
        "category": "Payload delivery",
        "value": "83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b",
        "timestamp": "1603642920",
        "comment": "vhash test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>vhash test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:File-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="FileObj:FileObjectType">
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">83e896c86267c97d0f7e21dbf0830a76777b81891bdb13dae4f28ba10f2c521b</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
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
    </indicator:Indicator>
    ```

- vulnerability
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "vulnerability",
        "category": "External analysis",
        "value": "CVE-2017-11774",
        "timestamp": "1603642920",
        "comment": "Vulnerability test attribute"
    }
    ```
  - STIX
    ```xml
    <!--To_ids flag by default is true here, but does not affect the result being a TTP-->
    <ttp:TTP id="MISP:TTP-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>External analysis: CVE-2017-11774 (MISP Attribute)</ttp:Title>
        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target id="MISP:ExploitTarget-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='et:ExploitTargetType'>
                    <et:Title>Vulnerability test attribute</et:Title>
                    <et:Vulnerability>
                        <et:CVE_ID>CVE-2017-11774</et:CVE_ID>
                    </et:Vulnerability>
                </stixCommon:Exploit_Target>
            </ttp:Exploit_Target>
        </ttp:Exploit_Targets>
    </ttp:TTP>
    ```

- weakness
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "weakness",
        "category": "External analysis",
        "value": "ABA9875413"
    }
    ```
  - STIX
    ```xml
    <!--To_ids flag by default is false here, but does not affect the result being a TTP-->
    <ttp:TTP id="MISP:TTP-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2021-01-12T13:43:56+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>External analysis: CWE-25 (MISP Attribute)</ttp:Title>
        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target id="MISP:ExploitTarget-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2021-01-12T13:43:56+00:00" xsi:type='et:ExploitTargetType'>
                    <et:Title>Weakness CWE-25</et:Title>
                    <et:Description>Weakness test attribute</et:Description>
                    <et:Weakness>
                        <et:CWE_ID>CWE-25</et:CWE_ID>
                    </et:Weakness>
                </stixCommon:Exploit_Target>
            </ttp:Exploit_Target>
        </ttp:Exploit_Targets>
    </ttp:TTP>
    ```

- whois-registrant-email
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "whois-registrant-email",
        "category": "Attribution",
        "value": "registrant@email.org",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:Whois-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                <WhoisObj:Registrants>
                    <WhoisObj:Registrant>
      <WhoisObj:Email_Address xsi:type="AddressObj:AddressObjectType" category="e-mail">
                            <AddressObj:Address_Value condition="Equals">registrant@email.org</AddressObj:Address_Value>
                        </WhoisObj:Email_Address>
                    </WhoisObj:Registrant>
                </WhoisObj:Registrants>
</cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- whois-registrant-name
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "whois-registrant-name",
        "category": "Attribution",
        "value": "Registrant Name",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
        <cybox:Object id="MISP-Project:Whois-518b4bcb-a86b-4783-9457-391d548b605b">
         <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                <WhoisObj:Registrants>
                    <WhoisObj:Registrant>
                        <WhoisObj:Name condition="Equals">Registrant Name</WhoisObj:Name>
                    </WhoisObj:Registrant>
                </WhoisObj:Registrants>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- whois-registrant-org
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "whois-registrant-org",
        "category": "Attribution",
        "value": "Registrant Org",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
        <cybox:Object id="MISP-Project:Whois-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
         <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                <WhoisObj:Registrants>
                    <WhoisObj:Registrant>
                        <WhoisObj:Organization condition="Equals">Registrant Org</WhoisObj:Organization>
                    </WhoisObj:Registrant>
                </WhoisObj:Registrants>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- whois-registrant-phone
  - MISP
    ```json
    {
        "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
        "type": "whois-registrant-phone",
        "category": "Attribution",
        "value": "0123456789",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
        <cybox:Object id="MISP-Project:Whois-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
            <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                <WhoisObj:Registrants>
                    <WhoisObj:Registrant>
                        <WhoisObj:Phone_Number condition="Equals">0123456789</WhoisObj:Phone_Number>
                    </WhoisObj:Registrant>
                </WhoisObj:Registrants>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- whois-registrar
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "whois-registrar",
        "category": "Attribution",
        "value": "Registrar.eu",
        "comment": "Whois registrat test attribute",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP-Project:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP-Project:Whois-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                <WhoisObj:Registrar_Info>
                    <WhoisObj:Name>Registrar.eu</WhoisObj:Name>
                </WhoisObj:Registrar_Info>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- windows-service-displayname
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "windows-service-displayname",
        "category": "Artifacts dropped",
        "value": "Report for bugs",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:WinService-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="WinServiceObj:WindowsServiceObjectType">
                <WinServiceObj:Display_Name>Report for bugs</WinServiceObj:Display_Name>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- windows-service-name
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "windows-service-name",
        "category": "Artifacts dropped",
        "value": "BUGREPORT",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
        <cybox:Object id="MISP:WinService-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Properties xsi:type="WinServiceObj:WindowsServiceObjectType">
                <WinServiceObj:Service_Name>BUGREPORT</WinServiceObj:Service_Name>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- x509-fingerprint-md5
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "x509-fingerprint-md5",
        "category": "Payload delivery",
        "value": "8764605c6f388c89096b534d33565802",
        "timestamp": "1603642920",
        "comment": "X509 MD5 fingerprint test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 8764605c6f388c89096b534d33565802 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>X509 MD5 fingerprint test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:X509Certificate-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="X509CertificateObj:X509CertificateObjectType">
                    <X509CertificateObj:Certificate_Signature>
                        <X509CertificateObj:Signature_Algorithm condition="Equals">MD5</X509CertificateObj:Signature_Algorithm>
                        <X509CertificateObj:Signature condition="Equals">8764605c6f388c89096b534d33565802</X509CertificateObj:Signature>
                    </X509CertificateObj:Certificate_Signature>
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
    </indicator:Indicator>
    ```

- x509-fingerprint-sha1
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "x509-fingerprint-sha1",
        "category": "Payload delivery",
        "value": "46aba99aa7158e4609aaa72b50990842fd22ae86",
        "timestamp": "1603642920",
        "comment": "X509 SHA1 fingerprint test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: 46aba99aa7158e4609aaa72b50990842fd22ae86 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>X509 SHA1 fingerprint test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Object id="MISP:X509Certificate-518b4bcb-a86b-4783-9457-391d548b605b">
                <cybox:Properties xsi:type="X509CertificateObj:X509CertificateObjectType">
                    <X509CertificateObj:Certificate_Signature>
                        <X509CertificateObj:Signature_Algorithm condition="Equals">SHA1</X509CertificateObj:Signature_Algorithm>
                        <X509CertificateObj:Signature condition="Equals">46aba99aa7158e4609aaa72b50990842fd22ae86</X509CertificateObj:Signature>
                    </X509CertificateObj:Certificate_Signature>
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
    </indicator:Indicator>
    ```

- x509-fingerprint-sha256
  - MISP
    ```json
    {
        "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
        "type": "x509-fingerprint-sha256",
        "category": "Payload delivery",
        "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b",
        "timestamp": "1603642920",
        "comment": "X509 SHA256 fingerprint test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-34cb1a7c-55ec-412a-8684-ba4a88d83a45" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload delivery: ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>X509 SHA256 fingerprint test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
            <cybox:Object id="MISP:X509Certificate-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
                <cybox:Properties xsi:type="X509CertificateObj:X509CertificateObjectType">
                    <X509CertificateObj:Certificate_Signature>
                        <X509CertificateObj:Signature_Algorithm condition="Equals">SHA256</X509CertificateObj:Signature_Algorithm>
                        <X509CertificateObj:Signature condition="Equals">ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b</X509CertificateObj:Signature>
                    </X509CertificateObj:Certificate_Signature>
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
    </indicator:Indicator>
    ```

- yara
  - MISP
    ```json
    {
        "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
        "type": "yara",
        "category": "Payload installation",
        "value": "import \"pe\" rule single_section{condition:pe.number_of_sections == 1}",
        "timestamp": "1603642920",
        "comment": "Yara test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <!--To_ids flag must be true since Observables have no Test_mechanisms field-->
    <indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Payload installation: import "pe" rule single_section{condition:pe.number_of_sections == 1} (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Yara test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Test_Mechanisms>
            <indicator:Test_Mechanism xsi:type='yaraTM:YaraTestMechanismType'>
                <yaraTM:Rule><![CDATA[{'value': 'import "pe" rule single_section{condition:pe.number_of_sections == 1}', 'encoded': True}]]></yaraTM:Rule>
            </indicator:Test_Mechanism>
        </indicator:Test_Mechanisms>
        <indicator:Confidence timestamp="2020-10-25T16:22:00+00:00">
            <stixCommon:Value>High</stixCommon:Value>
            <stixCommon:Description>Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none</stixCommon:Description>
        </indicator:Confidence>
        <indicator:Producer>
            <stixCommon:Identity>
                <stixCommon:Name>MISP</stixCommon:Name>
            </stixCommon:Identity>
        </indicator:Producer>
    </indicator:Indicator>
    ```


### Unmapped attribute types

You may have noticed we are very far from having all the attribute types supported. This is due to the various use cases that MISP can be used for.  
Nonetheless, every attribute whose type is not in the list, is exported as `Custom` object. Let us see some examples of custom objects exported from attributes:
- btc
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "btc",
        "category": "Financial fraud",
        "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE",
        "timestamp": "1603642920",
        "comment": "Btc test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <stixCommon:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Financial fraud:  1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE  (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Btc test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:Custom-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="CustomObj:CustomObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="btc"> 1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE </cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
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
    ```

- iban
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "iban",
        "category": "Financial fraud",
        "value": "LU1234567890ABCDEF1234567890",
        "timestamp": "1603642920",
        "comment": "IBAN test attribute",
        "to_ids": true
    }
    ```
  - STIX
    ```xml
    <stixCommon:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-10-25T16:22:00+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>Financial fraud: LU1234567890ABCDEF1234567890 (MISP Attribute)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>IBAN test attribute</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Object id="MISP:Custom-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                <cybox:Properties xsi:type="CustomObj:CustomObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="iban">LU1234567890ABCDEF1234567890</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
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
    ```

- phone-number
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "phone-number",
        "category": "Person",
        "value": "0123456789",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:Custom-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="CustomObj:CustomObjectType">
                <cyboxCommon:Custom_Properties>
                    <cyboxCommon:Property name="phone-number">0123456789</cyboxCommon:Property>
                </cyboxCommon:Custom_Properties>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```

- passport-number
  - MISP
    ```json
    {
        "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
        "type": "passport-number",
        "category": "Person",
        "value": "ABA9875413",
        "to_ids": false
    }
    ```
  - STIX
    ```xml
    <cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Object id="MISP:Custom-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
            <cybox:Properties xsi:type="CustomObj:CustomObjectType">
                <cyboxCommon:Custom_Properties>
                    <cyboxCommon:Property name="passport-number">ABA9875413</cyboxCommon:Property>
                </cyboxCommon:Custom_Properties>
            </cybox:Properties>
        </cybox:Object>
    </cybox:ObservableType>
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX1 mapping](misp_events_to_stix1.md)
- [Objects export to STIX1 mapping](misp_objects_to_stix1.md)
- [Galaxies export to STIX1 mapping](misp_galaxies_to_stix1.md)

([Go back to the main documentation](README.md))
