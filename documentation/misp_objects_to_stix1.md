# MISP Objects to STIX1 mapping

MISP Objects are containers of single MISP attributes that are grouped together to highlight their meaning in a real use case scenario.  
For instance, if you want to share a report with suspicious files, without object templates you would end up with a list of file names, hashes, and other attributes that are all mixed together, making the differentiation of each file difficult. In this case with the file object template, we simply group together all the attributes which belong to each file.  
The list of currently supported templates is available [here](https://github.com/MISP/misp-objects).

As we can see in the [detailed Events mapping documentation](misp_events_to_stix1.md), objects within their event are exported in different STIX objects embedded in a `STIX Package`. Indicators and observables are also embedded in the `Incident` but it is not the case for TTPS for instance.  
So for he rest of this documentation, in order to keep the content clear enough and to skip the irrelevant part, we will consider the followings:
- Indicators and observables are displayed as standalone objects, but we keep in mind that **if the related MISP objects are exported within their event, those STIX objects are actually exported within their Incident and STIX Package**
- We will give details about the context of each STIX object being neither an Indicator not an Observable case by case, since those ones are also displayed outside of their Incident or STIX package.
- In the following examples, every MISP object that has at least one attribute with a `to_ids` flag is exported within an indicator, but in any case the object attributes are contained in an observable object.
- More details given about the `to_ids` flag if necessary, case by case

### Current mapping

- asn
  - MISP
    ```json
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
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5b23c82b-6508-4bdc-b580-045b0a00020f" timestamp="2021-01-12T14:36:01+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: asn (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
        <indicator:Description>Autonomous system object describing an autonomous system</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5b23c82b-6508-4bdc-b580-045b0a00020f">
            <cybox:Object id="MISP:AS-5b23c82b-6508-4bdc-b580-045b0a00020f">
                <cybox:Properties xsi:type="ASObj:ASObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="subnet-announced">1.2.3.4</cyboxCommon:Property>
                        <cyboxCommon:Property name="subnet-announced">8.8.8.8</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <ASObj:Name>AS name</ASObj:Name>
                    <ASObj:Handle condition="Equals">AS66642</ASObj:Handle>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T14:36:01+00:00">
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

- attack-pattern
  - MISP
    ```json
    {
        "name": "attack-pattern",
        "meta-category": "vulnerability",
        "description": "Attack pattern describing a common attack pattern enumeration and classification.",
        "uuid": "7205da54-70de-4fa7-9b34-e14e63fe6787",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "id",
                "value": "9"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "Buffer Overflow in Local Command-Line Utilities"
            },
            {
                "type": "text",
                "object_relation": "summary",
                "value": "This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root."
            }
        ]
    }
    ```
  - STIX
    ```xml
    <ttp:TTP id="MISP:TTP-7205da54-70de-4fa7-9b34-e14e63fe6787" timestamp="2021-01-12T14:42:42+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>vulnerability: attack-pattern (MISP Object)</ttp:Title>
        <ttp:Behavior>
            <ttp:Attack_Patterns>
                <ttp:Attack_Pattern capec_id="CAPEC-9" id="MISP:AttackPattern-7205da54-70de-4fa7-9b34-e14e63fe6787">
                    <ttp:Title>Buffer Overflow in Local Command-Line Utilities</ttp:Title>
                    <ttp:Description>This attack targets command-line utilities available in a number of shells. An attacker can leverage a vulnerability found in a command-line utility to escalate privilege to root.</ttp:Description>
                </ttp:Attack_Pattern>
            </ttp:Attack_Patterns>
        </ttp:Behavior>
    </ttp:TTP>
    ```

- course-of-action
  - MISP
    ```json
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
                "value": "Block traffic to PIVY C2 Server (10.10.10.10)"
            },
            {
                "type": "text",
                "object_relation": "type",
                "value": "Perimeter Blocking"
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
    }
    ```
  - STIX
    ```xml
    <coa:Course_Of_Action id="MISP:CourseOfAction-5d514ff9-ac30-4fb5-b9e7-3eb4a964451a" timestamp="2021-01-12T14:44:56.158319+00:00" xsi:type='coa:CourseOfActionType'>
        <coa:Title>Block traffic to PIVY C2 Server (10.10.10.10)</coa:Title>
        <coa:Stage xsi:type="stixVocabs:COAStageVocab-1.0">Response</coa:Stage>
        <coa:Type xsi:type="stixVocabs:CourseOfActionTypeVocab-1.0">Perimeter Blocking</coa:Type>
        <coa:Objective>
            <coa:Description>Block communication between the PIVY agents and the C2 Server</coa:Description>
        </coa:Objective>
        <coa:Impact timestamp="2021-01-12T14:44:56.158436+00:00">
            <stixCommon:Value>Low</stixCommon:Value>
        </coa:Impact>
        <coa:Cost timestamp="2021-01-12T14:44:56.158417+00:00">
            <stixCommon:Value>Low</stixCommon:Value>
        </coa:Cost>
        <coa:Efficacy timestamp="2021-01-12T14:44:56.158458+00:00">
            <stixCommon:Value>High</stixCommon:Value>
        </coa:Efficacy>
    </coa:Course_Of_Action>
    ```

- credential
  - MISP
    ```json
    {
        "name": "credential",
        "meta-category": "misc",
        "description": "Credential describes one or more credential(s)",
        "uuid": "5b1f9378-46d4-494b-a4c1-044e0a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "text",
                "value": "MISP default credentials"
            },
            {
                "type": "text",
                "object_relation": "username",
                "value": "misp"
            },
            {
                "type": "text",
                "object_relation": "password",
                "value": "Password1234"
            },
            {
                "type": "text",
                "object_relation": "type",
                "value": "password"
            },
            {
                "type": "text",
                "object_relation": "origin",
                "value": "malware-analysis"
            },
            {
                "type": "text",
                "object_relation": "format",
                "value": "clear-text"
            },
            {
                "type": "text",
                "object_relation": "notification",
                "value": "victim-notified"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <stixCommon:RelatedObservableType>
        <stixCommon:Relationship>misc</stixCommon:Relationship>
        <stixCommon:Observable id="MISP:Observable-5b1f9378-46d4-494b-a4c1-044e0a00020f">
            <cybox:Object id="MISP:UserAccount-5b1f9378-46d4-494b-a4c1-044e0a00020f">
                <cybox:Properties xsi:type="UserAccountObj:UserAccountObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="origin">malware-analysis</cyboxCommon:Property>
                        <cyboxCommon:Property name="notification">victim-notified</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <AccountObj:Description>MISP default credentials</AccountObj:Description>
                    <AccountObj:Authentication>
                        <AccountObj:Authentication_Type>password</AccountObj:Authentication_Type>
                        <AccountObj:Authentication_Data>Password1234</AccountObj:Authentication_Data>
                        <AccountObj:Structured_Authentication_Mechanism>
                            <AccountObj:Description>clear-text</AccountObj:Description>
                        </AccountObj:Structured_Authentication_Mechanism>
                    </AccountObj:Authentication>
                    <UserAccountObj:Username>misp</UserAccountObj:Username>
                </cybox:Properties>
            </cybox:Object>
        </stixCommon:Observable>
    </stixCommon:RelatedObservableType>
    ```

- domain-ip
  - MISP
    ```json
    {
        "name": "domain-ip",
        "meta-category": "network",
        "description": "A domain and IP address seen as a tuple",
        "uuid": "5ac337df-e078-4e99-8b17-02550a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "type": "domain",
                "object_relation": "domain",
                "value": "circl.lu"
            },
            {
                "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                "type": "ip-dst",
                "object_relation": "ip",
                "value": "149.13.33.14"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac337df-e078-4e99-8b17-02550a00020f" timestamp="2021-01-12T15:20:16+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: domain-ip (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
        <indicator:Description>A domain and IP address seen as a tuple</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:domain-ip_ObservableComposition-5ac337df-e078-4e99-8b17-02550a00020f">
            <cybox:Observable_Composition operator="AND">
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Object id="MISP:DomainName-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
                            <DomainNameObj:Value condition="Equals">circl.lu</DomainNameObj:Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
                    <cybox:Object id="MISP:Address-518b4bcb-a86b-4783-9457-391d548b605b">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">149.13.33.14</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </cybox:Observable_Composition>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:20:16+00:00">
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

- email
  - MISP
    ```json
    {
        "name": "email",
        "meta-category": "network",
        "description": "Email object describing an email with meta-information",
        "uuid": "5e396622-2a54-4c8d-b61d-159da964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "email-src",
                "object_relation": "from",
                "value": "source@email.test"
            },
            {
                "type": "email-dst",
                "object_relation": "to",
                "value": "destination@email.test"
            },
            {
                "type": "email-dst",
                "object_relation": "cc",
                "value": "cc1@email.test"
            },
            {
                "type": "email-dst",
                "object_relation": "cc",
                "value": "cc2@email.test"
            },
            {
                "type": "email-reply-to",
                "object_relation": "reply-to",
                "value": "reply-to@email.test"
            },
            {
                "type": "email-subject",
                "object_relation": "subject",
                "value": "Email test subject"
            },
            {
                "type": "email-attachment",
                "object_relation": "attachment",
                "value": "attachment1.file"
            },
            {
                "type": "email-attachment",
                "object_relation": "attachment",
                "value": "attachment2.file"
            },
            {
                "type": "email-x-mailer",
                "object_relation": "x-mailer",
                "value": "x-mailer-test"
            },
            {
                "type": "text",
                "object_relation": "user-agent",
                "value": "Test user agent"
            },
            {
                "type": "email-mime-boundary",
                "object_relation": "mime-boundary",
                "value": "Test mime boundary"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5e396622-2a54-4c8d-b61d-159da964451a" timestamp="2021-01-12T15:23:22+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: email (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malicious E-mail</indicator:Type>
        <indicator:Description>Email object describing an email with meta-information</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5e396622-2a54-4c8d-b61d-159da964451a">
            <cybox:Object id="MISP:EmailMessage-5e396622-2a54-4c8d-b61d-159da964451a">
                <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
                    <EmailMessageObj:Header>
                        <EmailMessageObj:To>
                            <EmailMessageObj:Recipient xsi:type="AddressObj:AddressObjectType" category="e-mail">
                                <AddressObj:Address_Value>destination@email.test</AddressObj:Address_Value>
                            </EmailMessageObj:Recipient>
                        </EmailMessageObj:To>
                        <EmailMessageObj:CC>
                            <EmailMessageObj:Recipient xsi:type="AddressObj:AddressObjectType" category="e-mail">
                                <AddressObj:Address_Value>cc1@email.test</AddressObj:Address_Value>
                            </EmailMessageObj:Recipient>
                            <EmailMessageObj:Recipient xsi:type="AddressObj:AddressObjectType" category="e-mail">
                                <AddressObj:Address_Value>cc2@email.test</AddressObj:Address_Value>
                            </EmailMessageObj:Recipient>
                        </EmailMessageObj:CC>
                        <EmailMessageObj:From xsi:type="AddressObj:AddressObjectType" category="e-mail">
                            <AddressObj:Address_Value condition="Equals">source@email.test</AddressObj:Address_Value>
                        </EmailMessageObj:From>
                        <EmailMessageObj:Subject condition="Equals">Email test subject</EmailMessageObj:Subject>
                        <EmailMessageObj:Reply_To xsi:type="AddressObj:AddressObjectType" category="e-mail">
                            <AddressObj:Address_Value condition="Equals">reply-to@email.test</AddressObj:Address_Value>
                        </EmailMessageObj:Reply_To>
                        <EmailMessageObj:Boundary condition="Equals">Test mime boundary</EmailMessageObj:Boundary>
                        <EmailMessageObj:User_Agent condition="Equals">Test user agent</EmailMessageObj:User_Agent>
                        <EmailMessageObj:X_Mailer condition="Equals">x-mailer-test</EmailMessageObj:X_Mailer>
                    </EmailMessageObj:Header>
                    <EmailMessageObj:Attachments>
                        <EmailMessageObj:File object_reference="MISP:FileObject-d507ecc5-0285-4aae-9e20-b66b982b4138"/>
                        <EmailMessageObj:File object_reference="MISP:FileObject-c5c7a683-7a2b-418a-af4a-773b131f918b"/>
                    </EmailMessageObj:Attachments>
                </cybox:Properties>
                <cybox:Related_Objects>
                    <cybox:Related_Object id="MISP:FileObject-d507ecc5-0285-4aae-9e20-b66b982b4138">
                        <cybox:Properties xsi:type="FileObj:FileObjectType">
                            <FileObj:File_Name condition="Equals">attachment1.file</FileObj:File_Name>
                        </cybox:Properties>
                        <cybox:Relationship xsi:type="cyboxVocabs:ObjectRelationshipVocab-1.1">Contains</cybox:Relationship>
                    </cybox:Related_Object>
                    <cybox:Related_Object id="MISP:FileObject-c5c7a683-7a2b-418a-af4a-773b131f918b">
                        <cybox:Properties xsi:type="FileObj:FileObjectType">
                            <FileObj:File_Name condition="Equals">attachment2.file</FileObj:File_Name>
                        </cybox:Properties>
                        <cybox:Relationship xsi:type="cyboxVocabs:ObjectRelationshipVocab-1.1">Contains</cybox:Relationship>
                    </cybox:Related_Object>
                </cybox:Related_Objects>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:23:22+00:00">
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

- file
  - MISP
    ```json
    {
        "name": "file",
        "meta-category": "file",
        "description": "File object describing a file with meta-information",
        "uuid": "5e384ae7-672c-4250-9cda-3b4da964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "type": "malware-sample",
                "object_relation": "malware-sample",
                "value": "oui|8764605c6f388c89096b534d33565802",
                "data": "UEsDBAoACQAAAPKLQ1AvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAA+dKOF7nSjhedXgLAAEEIQAAAAQhAAAA7ukeownnAQsmsimPVT3qvMUSCRqPjj3xfZpK3MTLpCrssX1AVtxZoMh3ucu5mCxQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAPKLQ1BAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAPnSjhe50o4XnV4CwABBCEAAAAEIQAAAFHTwHeSOtOjQMWS6+0aN1BLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAADyi0NQL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAA+dKOF51eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAADyi0NQQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAPnSjhedXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA=="
            },
            {
                "type": "filename",
                "object_relation": "filename",
                "value": "oui"
            },
            {
                "type": "md5",
                "object_relation": "md5",
                "value": "8764605c6f388c89096b534d33565802"
            },
            {
                "type": "sha1",
                "object_relation": "sha1",
                "value": "46aba99aa7158e4609aaa72b50990842fd22ae86"
            },
            {
                "type": "sha256",
                "object_relation": "sha256",
                "value": "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
            },
            {
                "type": "size-in-bytes",
                "object_relation": "size-in-bytes",
                "value": "35"
            },
            {
                "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                "type": "attachment",
                "object_relation": "attachment",
                "value": "non",
                "data": "Tm9uLW1hbGljaW91cyBmaWxlCg=="
            },
            {
                "type": "text",
                "object_relation": "path",
                "value": "/var/www/MISP/app/files/scripts/tmp"
            },
            {
                "type": "text",
                "object_relation": "file-encoding",
                "value": "UTF-8"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5e384ae7-672c-4250-9cda-3b4da964451a" timestamp="2021-01-12T15:31:12+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>file: file (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>File object describing a file with meta-information</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:file_ObservableComposition-5e384ae7-672c-4250-9cda-3b4da964451a">
            <cybox:Observable_Composition operator="AND">
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Title>oui</cybox:Title>
                    <cybox:Object id="MISP:Artifact-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="ArtifactObj:ArtifactObjectType">
                            <ArtifactObj:Hashes>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">8764605c6f388c89096b534d33565802</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                            </ArtifactObj:Hashes>
                            <ArtifactObj:Raw_Artifact condition="Equals"><![CDATA[UEsDBAoACQAAAPKLQ1AvUbiwLwAAACMAAAAgABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAkAA+dKOF7nSjhedXgLAAEEIQAAAAQhAAAA7ukeownnAQsmsimPVT3qvMUSCRqPjj3xfZpK3MTLpCrssX1AVtxZoMh3ucu5mCxQSwcIL1G4sC8AAAAjAAAAUEsDBAoACQAAAPKLQ1BAAezaDwAAAAMAAAAtABwAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQJAAPnSjhe50o4XnV4CwABBCEAAAAEIQAAAFHTwHeSOtOjQMWS6+0aN1BLBwhAAezaDwAAAAMAAABQSwECHgMKAAkAAADyi0NQL1G4sC8AAAAjAAAAIAAYAAAAAAABAAAApIEAAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDJVVAUAA+dKOF51eAsAAQQhAAAABCEAAABQSwECHgMKAAkAAADyi0NQQAHs2g8AAAADAAAALQAYAAAAAAABAAAApIGZAAAAODc2NDYwNWM2ZjM4OGM4OTA5NmI1MzRkMzM1NjU4MDIuZmlsZW5hbWUudHh0VVQFAAPnSjhedXgLAAEEIQAAAAQhAAAAUEsFBgAAAAACAAIA2QAAAB8BAAAAAA==]]></ArtifactObj:Raw_Artifact>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
                    <cybox:Title>non</cybox:Title>
                    <cybox:Object id="MISP:Artifact-518b4bcb-a86b-4783-9457-391d548b605b">
                        <cybox:Properties xsi:type="ArtifactObj:ArtifactObjectType">
                            <ArtifactObj:Raw_Artifact condition="Equals"><![CDATA[Tm9uLW1hbGljaW91cyBmaWxlCg==]]></ArtifactObj:Raw_Artifact>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-5e384ae7-672c-4250-9cda-3b4da964451a">
                    <cybox:Object id="MISP:File-5e384ae7-672c-4250-9cda-3b4da964451a">
                        <cybox:Properties xsi:type="FileObj:FileObjectType">
                            <cyboxCommon:Custom_Properties>
                                <cyboxCommon:Property name="file-encoding">UTF-8</cyboxCommon:Property>
                            </cyboxCommon:Custom_Properties>
                            <FileObj:File_Name condition="Equals">oui</FileObj:File_Name>
                            <FileObj:File_Path condition="Equals">/var/www/MISP/app/files/scripts/tmp</FileObj:File_Path>
                            <FileObj:Size_In_Bytes condition="Equals">35</FileObj:Size_In_Bytes>
                            <FileObj:Hashes>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">8764605c6f388c89096b534d33565802</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">46aba99aa7158e4609aaa72b50990842fd22ae86</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                            </FileObj:Hashes>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </cybox:Observable_Composition>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:31:12+00:00">
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

- file (with references to pe & pe-section(s))
  - MISP
    ```json
    [
        {
            "name": "file",
            "meta-category": "file",
            "description": "File object describing a file with meta-information",
            "uuid": "5ac47782-e1b8-40b6-96b4-02510a00020f",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "filename",
                    "object_relation": "filename",
                    "value": "oui"
                },
                {
                    "type": "md5",
                    "object_relation": "md5",
                    "value": "b2a5abfeef9e36964281a31e17b57c97"
                },
                {
                    "type": "sha1",
                    "object_relation": "sha1",
                    "value": "5898fc860300e228dcd54c0b1045b5fa0dcda502"
                },
                {
                    "type": "sha256",
                    "object_relation": "sha256",
                    "value": "3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8"
                },
                {
                    "type": "size-in-bytes",
                    "object_relation": "size-in-bytes",
                    "value": "1234"
                },
                {
                    "type": "float",
                    "object_relation": "entropy",
                    "value": "1.234"
                }
            ],
            "ObjectReference": [
                {
                    "referenced_uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
                    "relationship_type": "includes",
                    "Object": {
                        "uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
                        "name": "pe",
                        "meta-category": "file"
                    }
                }
            ]
        },
        {
            "name": "pe",
            "meta-category": "file",
            "description": "Object describing a Portable Executable",
            "uuid": "2183705f-e8d6-4c08-a820-5b56a1303bb1",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "type",
                    "value": "exe"
                },
                {
                    "type": "datetime",
                    "object_relation": "compilation-timestamp",
                    "value": "2019-03-16T12:31:22"
                },
                {
                    "type": "text",
                    "object_relation": "entrypoint-address",
                    "value": "5369222868"
                },
                {
                    "type": "filename",
                    "object_relation": "original-filename",
                    "value": "PuTTy"
                },
                {
                    "type": "filename",
                    "object_relation": "internal-filename",
                    "value": "PuTTy"
                },
                {
                    "type": "text",
                    "object_relation": "file-description",
                    "value": "SSH, Telnet and Rlogin client"
                },
                {
                    "type": "text",
                    "object_relation": "file-version",
                    "value": "Release 0.71 (with embedded help)"
                },
                {
                    "type": "text",
                    "object_relation": "lang-id",
                    "value": "080904B0"
                },
                {
                    "type": "text",
                    "object_relation": "product-name",
                    "value": "PuTTy suite"
                },
                {
                    "type": "text",
                    "object_relation": "product-version",
                    "value": "Release 0.71"
                },
                {
                    "type": "text",
                    "object_relation": "company-name",
                    "value": "Simoe Tatham"
                },
                {
                    "type": "text",
                    "object_relation": "legal-copyright",
                    "value": "Copyright \u00a9 1997-2019 Simon Tatham."
                },
                {
                    "type": "counter",
                    "object_relation": "number-sections",
                    "value": "8"
                },
                {
                    "type": "imphash",
                    "object_relation": "imphash",
                    "value": "23ea835ab4b9017c74dfb023d2301c99"
                },
                {
                    "type": "impfuzzy",
                    "object_relation": "impfuzzy",
                    "value": "192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt"
                }
            ],
            "ObjectReference": [
                {
                    "referenced_uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
                    "relationship_type": "includes",
                    "Object": {
                        "uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
                        "name": "pe-section",
                        "meta-category": "file"
                    }
                }
            ]
        },
        {
            "name": "pe-section",
            "meta-category": "file",
            "description": "Object describing a section of a Portable Executable",
            "uuid": "68bd413b-5392-4239-93a9-e574fb80af8c",
            "timestamp": "1603642920",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name",
                    "value": ".rsrc"
                },
                {
                    "type": "size-in-bytes",
                    "object_relation": "size-in-bytes",
                    "value": "305152"
                },
                {
                    "type": "float",
                    "object_relation": "entropy",
                    "value": "7.836462238824369"
                },
                {
                    "type": "md5",
                    "object_relation": "md5",
                    "value": "8a2a5fc2ce56b3b04d58539a95390600"
                },
                {
                    "type": "sha1",
                    "object_relation": "sha1",
                    "value": "0aeb9def096e9f73e9460afe6f8783a32c7eabdf"
                },
                {
                    "type": "sha256",
                    "object_relation": "sha256",
                    "value": "c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b"
                },
                {
                    "type": "sha512",
                    "object_relation": "sha512",
                    "value": "98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f"
                },
                {
                    "type": "ssdeep",
                    "object_relation": "ssdeep",
                    "value": "6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ/UjHSEuSvK"
                }
            ]
        }
    ]
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac47782-e1b8-40b6-96b4-02510a00020f" timestamp="2021-01-12T15:28:54+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>file: file (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
        <indicator:Description>File object describing a file with meta-information</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5ac47782-e1b8-40b6-96b4-02510a00020f">
            <cybox:Object id="MISP:WindowsExecutableFile-5ac47782-e1b8-40b6-96b4-02510a00020f">
                <cybox:Properties xsi:type="WinExecutableFileObj:WindowsExecutableFileObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="compilation-timestamp">2019-03-16T12:31:22</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <FileObj:File_Name condition="Equals">oui</FileObj:File_Name>
                    <FileObj:Size_In_Bytes condition="Equals">1234</FileObj:Size_In_Bytes>
                    <FileObj:Hashes>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">b2a5abfeef9e36964281a31e17b57c97</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">5898fc860300e228dcd54c0b1045b5fa0dcda502</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                        <cyboxCommon:Hash>
                            <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                            <cyboxCommon:Simple_Hash_Value condition="Equals">3a3468fa89b2ab7cbfe5400858a8ec0066e9e8defa9a64c993b5f24210244df8</cyboxCommon:Simple_Hash_Value>
                        </cyboxCommon:Hash>
                    </FileObj:Hashes>
                    <FileObj:Peak_Entropy condition="Equals">1.234</FileObj:Peak_Entropy>
                    <WinExecutableFileObj:Headers>
                        <WinExecutableFileObj:File_Header>
                            <WinExecutableFileObj:Number_Of_Sections condition="Equals">8</WinExecutableFileObj:Number_Of_Sections>
                            <WinExecutableFileObj:Hashes>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">23ea835ab4b9017c74dfb023d2301c99</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">192:8GMV5iqHKV+5RvUV5iqHKV+5RvAVDNNhwkCtRxwUQt63yf2y9sAkexSECI:vMVzB5R8VzB5R4XGtRxwUccc2y9scxt</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                            </WinExecutableFileObj:Hashes>
                        </WinExecutableFileObj:File_Header>
                        <WinExecutableFileObj:Optional_Header>
                            <WinExecutableFileObj:Address_Of_Entry_Point condition="Equals">5369222868</WinExecutableFileObj:Address_Of_Entry_Point>
                        </WinExecutableFileObj:Optional_Header>
                    </WinExecutableFileObj:Headers>
                    <WinExecutableFileObj:Resources>
                        <WinExecutableFileObj:VersionInfoResource xsi:type='WinExecutableFileObj:PEVersionInfoResourceType'>
                            <WinExecutableFileObj:CompanyName condition="Equals">Simoe Tatham</WinExecutableFileObj:CompanyName>
                            <WinExecutableFileObj:FileDescription condition="Equals">SSH, Telnet and Rlogin client</WinExecutableFileObj:FileDescription>
                            <WinExecutableFileObj:FileVersion condition="Equals">Release 0.71 (with embedded help)</WinExecutableFileObj:FileVersion>
                            <WinExecutableFileObj:InternalName condition="Equals">PuTTy</WinExecutableFileObj:InternalName>
                            <WinExecutableFileObj:LangID condition="Equals">080904B0</WinExecutableFileObj:LangID>
                            <WinExecutableFileObj:LegalCopyright condition="Equals">Copyright © 1997-2019 Simon Tatham./WinExecutableFileObj:LegalCopyright>
                            <WinExecutableFileObj:OriginalFilename condition="Equals">PuTTy</WinExecutableFileObj:OriginalFilename>
                            <WinExecutableFileObj:ProductName condition="Equals">PuTTy suite</WinExecutableFileObj:ProductName>
                            <WinExecutableFileObj:ProductVersion condition="Equals">Release 0.71</WinExecutableFileObj:ProductVersion>
                        </WinExecutableFileObj:VersionInfoResource>
                    </WinExecutableFileObj:Resources>
                    <WinExecutableFileObj:Sections>
                        <WinExecutableFileObj:Section>
                            <WinExecutableFileObj:Section_Header>
                                <WinExecutableFileObj:Name condition="Equals">.rsrc</WinExecutableFileObj:Name>
                                <WinExecutableFileObj:Size_Of_Raw_Data condition="Equals">305152</WinExecutableFileObj:Size_Of_Raw_Data>
                            </WinExecutableFileObj:Section_Header>
                            <WinExecutableFileObj:Data_Hashes>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">8a2a5fc2ce56b3b04d58539a95390600</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">0aeb9def096e9f73e9460afe6f8783a32c7eabdf</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">c6b3ac8303a72be90b0e47f69977e6f5665693d4ea0aa93e5c27b5c556c7cf9b</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA512</cyboxCommon:Type>
                                    <cyboxCommon:Simple_Hash_Value condition="Equals">98fce208e6ed9612db53725fe03b73ab7cb1b487814d521c3c218273cad33891ce832c4f842c6f492d92df1e78414c82a00ddb91a1f8ec7d67325231a597a78f</cyboxCommon:Simple_Hash_Value>
                                </cyboxCommon:Hash>
                                <cyboxCommon:Hash>
                                    <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SSDEEP</cyboxCommon:Type>
                                    <cyboxCommon:Fuzzy_Hash_Value>6144:BvqbV6zoA5yJJ1entjx+UJlVshhKuqMrgyNhahL2uSvhM:BvuVy5UJUtwUJ\/UjHSEuSvK</cyboxCommon:Fuzzy_Hash_Value>
                                </cyboxCommon:Hash>
                            </WinExecutableFileObj:Data_Hashes>
                            <WinExecutableFileObj:Entropy>
                                <WinExecutableFileObj:Value>7.836462238824369</WinExecutableFileObj:Value>
                            </WinExecutableFileObj:Entropy>
                        </WinExecutableFileObj:Section>
                    </WinExecutableFileObj:Sections>
                    <WinExecutableFileObj:Type condition="Equals">exe</WinExecutableFileObj:Type>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:28:54+00:00">
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

- ip-port
  - MISP
    ```json
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
                "value": "149.13.33.14"
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
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac47edc-31e4-4402-a7b6-040d0a00020f" timestamp="2021-01-12T15:34:10+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: ip-port (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>An IP address (or domain) and a port</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:ip-port_ObservableComposition-5ac47edc-31e4-4402-a7b6-040d0a00020f">
            <cybox:Observable_Composition operator="AND">
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Object id="MISP:Address-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">149.13.33.14</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
                    <cybox:Object id="MISP:dstPort-518b4bcb-a86b-4783-9457-391d548b605b">
                        <cybox:Properties xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">443</PortObj:Port_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
                    <cybox:Object id="MISP:DomainName-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
                        <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
                            <DomainNameObj:Value condition="Equals">circl.lu</DomainNameObj:Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </cybox:Observable_Composition>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:34:10+00:00">
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
        "name": "mutex",
        "meta-category": "misc",
        "description": "Object to describe mutual exclusion locks (mutex) as seen in memory or computer program",
        "uuid": "b0f55591-6a63-4fbd-a169-064e64738d95",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "name",
                "value": "MutexTest"
            },
            {
                "type": "text",
                "object_relation": "description",
                "value": "Test mutex on unix"
            },
            {
                "type": "text",
                "object_relation": "operating-system",
                "value": "Unix"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <MutexObj:MutexObjectType xsi:type="MutexObj:MutexObjectType">
        <cyboxCommon:Custom_Properties>
            <cyboxCommon:Property name="description">Test mutex on unix</cyboxCommon:Property>
            <cyboxCommon:Property name="operating-system">Unix</cyboxCommon:Property>
        </cyboxCommon:Custom_Properties>
        <MutexObj:Name>MutexTest</MutexObj:Name>
    </MutexObj:MutexObjectType>
    ```

- network-connection
  - MISP
    ```json
    {
        "name": "network-connection",
        "meta-category": "network",
        "description": "A local or remote network connection",
        "uuid": "5afacc53-c0b0-4825-a6ee-03c80a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "ip-src",
                "object_relation": "ip-src",
                "value": "1.2.3.4"
            },
            {
                "type": "ip-dst",
                "object_relation": "ip-dst",
                "value": "5.6.7.8"
            },
            {
                "type": "port",
                "object_relation": "src-port",
                "value": "8080"
            },
            {
                "type": "port",
                "object_relation": "dst-port",
                "value": "8080"
            },
            {
                "type": "hostname",
                "object_relation": "hostname-dst",
                "value": "circl.lu"
            },
            {
                "type": "text",
                "object_relation": "layer3-protocol",
                "value": "IP"
            },
            {
                "type": "text",
                "object_relation": "layer4-protocol",
                "value": "TCP"
            },
            {
                "type": "text",
                "object_relation": "layer7-protocol",
                "value": "HTTP"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5afacc53-c0b0-4825-a6ee-03c80a00020f" timestamp="2021-01-12T15:34:57+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: network-connection (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>A local or remote network connection</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5afacc53-c0b0-4825-a6ee-03c80a00020f">
            <cybox:Object id="MISP:NetworkConnection-5afacc53-c0b0-4825-a6ee-03c80a00020f">
                <cybox:Properties xsi:type="NetworkConnectionObj:NetworkConnectionObjectType">
                    <NetworkConnectionObj:Layer3_Protocol condition="Equals">IP</NetworkConnectionObj:Layer3_Protocol>
                    <NetworkConnectionObj:Layer4_Protocol condition="Equals">TCP</NetworkConnectionObj:Layer4_Protocol>
                    <NetworkConnectionObj:Layer7_Protocol condition="Equals">HTTP</NetworkConnectionObj:Layer7_Protocol>
                    <NetworkConnectionObj:Source_Socket_Address xsi:type="SocketAddressObj:SocketAddressObjectType">
                        <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="true" is_destination="false">
                            <AddressObj:Address_Value condition="Equals">1.2.3.4</AddressObj:Address_Value>
                        </SocketAddressObj:IP_Address>
                        <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">8080</PortObj:Port_Value>
                        </SocketAddressObj:Port>
                    </NetworkConnectionObj:Source_Socket_Address>
                    <NetworkConnectionObj:Destination_Socket_Address xsi:type="SocketAddressObj:SocketAddressObjectType">
                        <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">5.6.7.8</AddressObj:Address_Value>
                        </SocketAddressObj:IP_Address>
                        <SocketAddressObj:Hostname xsi:type="HostnameObj:HostnameObjectType">
                            <HostnameObj:Hostname_Value condition="Equals">circl.lu</HostnameObj:Hostname_Value>
                        </SocketAddressObj:Hostname>
                        <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">8080</PortObj:Port_Value>
                        </SocketAddressObj:Port>
                    </NetworkConnectionObj:Destination_Socket_Address>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:34:57+00:00">
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

- network-socket
  - MISP
    ```json
    {
        "name": "network-socket",
        "meta-category": "network",
        "description": "Network socket object describes a local or remote network connections based on the socket data structure",
        "uuid": "5afb3223-0988-4ef1-a920-02070a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "ip-src",
                "object_relation": "ip-src",
                "value": "1.2.3.4"
            },
            {
                "type": "ip-dst",
                "object_relation": "ip-dst",
                "value": "5.6.7.8"
            },
            {
                "type": "port",
                "object_relation": "src-port",
                "value": "8080"
            },
            {
                "type": "port",
                "object_relation": "dst-port",
                "value": "8080"
            },
            {
                "type": "hostname",
                "object_relation": "hostname-dst",
                "value": "circl.lu"
            },
            {
                "type": "text",
                "object_relation": "address-family",
                "value": "AF_FILE"
            },
            {
                "type": "text",
                "object_relation": "domain-family",
                "value": "PF_INET"
            },
            {
                "type": "text",
                "object_relation": "state",
                "value": "listening"
            },
            {
                "type": "text",
                "object_relation": "protocol",
                "value": "TCP"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5afb3223-0988-4ef1-a920-02070a00020f" timestamp="2021-01-12T15:35:58+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: network-socket (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Network socket object describes a local or remote network connections based on the socket data structure</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5afb3223-0988-4ef1-a920-02070a00020f">
            <cybox:Object id="MISP:NetworkSocket-5afb3223-0988-4ef1-a920-02070a00020f">
                <cybox:Properties xsi:type="NetworkSocketObj:NetworkSocketObjectType" is_blocking="false" is_listening="true">
                    <NetworkSocketObj:Address_Family condition="Equals">AF_FILE</NetworkSocketObj:Address_Family>
                    <NetworkSocketObj:Domain condition="Equals">PF_INET</NetworkSocketObj:Domain>
                    <NetworkSocketObj:Local_Address xsi:type="SocketAddressObj:SocketAddressObjectType">
                        <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="true" is_destination="false">
                            <AddressObj:Address_Value condition="Equals">1.2.3.4</AddressObj:Address_Value>
                        </SocketAddressObj:IP_Address>
                        <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">8080</PortObj:Port_Value>
                        </SocketAddressObj:Port>
                    </NetworkSocketObj:Local_Address>
                    <NetworkSocketObj:Protocol condition="Equals">TCP</NetworkSocketObj:Protocol>
                    <NetworkSocketObj:Remote_Address xsi:type="SocketAddressObj:SocketAddressObjectType">
                        <SocketAddressObj:IP_Address xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">5.6.7.8</AddressObj:Address_Value>
                        </SocketAddressObj:IP_Address>
                        <SocketAddressObj:Hostname xsi:type="HostnameObj:HostnameObjectType">
                            <HostnameObj:Hostname_Value condition="Equals">circl.lu</HostnameObj:Hostname_Value>
                        </SocketAddressObj:Hostname>
                        <SocketAddressObj:Port xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">8080</PortObj:Port_Value>
                        </SocketAddressObj:Port>
                    </NetworkSocketObj:Remote_Address>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:35:58+00:00">
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

- process
  - MISP
    ```json
    {
        "name": "process",
        "meta-category": "misc",
        "description": "Object describing a system process.",
        "uuid": "5e39776a-b284-40b3-8079-22fea964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "pid",
                "value": "2510"
            },
            {
                "type": "text",
                "object_relation": "child-pid",
                "value": "1401"
            },
            {
                "type": "text",
                "object_relation": "parent-pid",
                "value": "2107"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "test_process.exe"
            },
            {
                "type": "filename",
                "object_relation": "image",
                "value": "TestProcess"
            },
            {
                "type": "port",
                "object_relation": "port",
                "value": "1234"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5e39776a-b284-40b3-8079-22fea964451a" timestamp="2021-01-12T15:37:53+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>misc: process (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Object describing a system process.</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5e39776a-b284-40b3-8079-22fea964451a">
            <cybox:Object id="MISP:Process-5e39776a-b284-40b3-8079-22fea964451a">
                <cybox:Properties xsi:type="ProcessObj:ProcessObjectType">
                    <ProcessObj:PID condition="Equals">2510</ProcessObj:PID>
                    <ProcessObj:Name condition="Equals">test_process.exe</ProcessObj:Name>
                    <ProcessObj:Parent_PID condition="Equals">2107</ProcessObj:Parent_PID>
                    <ProcessObj:Child_PID_List>
                        <ProcessObj:Child_PID>1401</ProcessObj:Child_PID>
                    </ProcessObj:Child_PID_List>
                    <ProcessObj:Image_Info>
                        <ProcessObj:File_Name condition="Equals">TestProcess</ProcessObj:File_Name>
                    </ProcessObj:Image_Info>
                    <ProcessObj:Port_List>
                        <ProcessObj:Port xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">1234</PortObj:Port_Value>
                        </ProcessObj:Port>
                    </ProcessObj:Port_List>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:37:53+00:00">
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

- registry-key
  - MISP
    ```json
    {
        "name": "registry-key",
        "meta-category": "file",
        "description": "Registry key object describing a Windows registry key",
        "uuid": "5ac3379c-3e74-44ba-9160-04120a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "regkey",
                "object_relation": "key",
                "value": "hkey_local_machine\\system\\bar\\foo"
            },
            {
                "type": "text",
                "object_relation": "hive",
                "value": "hklm"
            },
            {
                "type": "text",
                "object_relation": "name",
                "value": "RegistryName"
            },
            {
                "type": "text",
                "object_relation": "data",
                "value": "qwertyuiop"
            },
            {
                "type": "text",
                "object_relation": "data-type",
                "value": "REG_SZ"
            },
            {
                "type": "datetime",
                "object_relation": "last-modified",
                "value": "2020-10-25T16:22:00"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac3379c-3e74-44ba-9160-04120a00020f" timestamp="2021-01-12T15:38:46+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>file: registry-key (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Registry key object describing a Windows registry key</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5ac3379c-3e74-44ba-9160-04120a00020f">
            <cybox:Object id="MISP:WindowsRegistryKey-5ac3379c-3e74-44ba-9160-04120a00020f">
                <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                    <WinRegistryKeyObj:Key condition="Equals">hkey_local_machine\system\bar\foo</WinRegistryKeyObj:Key>
                    <WinRegistryKeyObj:Hive condition="Equals">HKEY_LOCAL_MACHINE</WinRegistryKeyObj:Hive>
                    <WinRegistryKeyObj:Values>
                        <WinRegistryKeyObj:Value>
                            <WinRegistryKeyObj:Name condition="Equals">RegistryName</WinRegistryKeyObj:Name>
                            <WinRegistryKeyObj:Data condition="Equals">qwertyuiop</WinRegistryKeyObj:Data>
                            <WinRegistryKeyObj:Datatype condition="Equals">REG_SZ</WinRegistryKeyObj:Datatype>
                        </WinRegistryKeyObj:Value>
                    </WinRegistryKeyObj:Values>
                    <WinRegistryKeyObj:Modified_Time condition="Equals">2020-10-25T16:22:00</WinRegistryKeyObj:Modified_Time>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:38:46+00:00">
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

- url
  - MISP
    ```json
    {
        "name": "url",
        "meta-category": "network",
        "description": "url object describes an url along with its normalized field",
        "uuid": "5ac347ca-dac4-4562-9775-04120a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
                "type": "url",
                "object_relation": "url",
                "value": "https://www.circl.lu/team"
            },
            {
                "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
                "type": "domain",
                "object_relation": "domain",
                "value": "circl.lu"
            },
            {
                "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
                "type": "hostname",
                "object_relation": "host",
                "value": "www.circl.lu"
            },
            {
                "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
                "type": "ip-dst",
                "object_relation": "ip",
                "value": "149.13.33.14"
            },
            {
                "uuid": "f2259650-bc33-4b64-a3a8-a324aa7ea6bb",
                "type": "port",
                "object_relation": "port",
                "value": "443"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac347ca-dac4-4562-9775-04120a00020f" timestamp="2021-01-12T15:39:53+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: url (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
        <indicator:Description>url object describes an url along with its normalized field</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:url_ObservableComposition-5ac347ca-dac4-4562-9775-04120a00020f">
            <cybox:Observable_Composition operator="AND">
                <cybox:Observable id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                    <cybox:Object id="MISP:URI-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
                        <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                            <URIObj:Value condition="Equals">https://www.circl.lu/team</URIObj:Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
                    <cybox:Object id="MISP:DomainName-518b4bcb-a86b-4783-9457-391d548b605b">
                        <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
                            <DomainNameObj:Value condition="Equals">circl.lu</DomainNameObj:Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
                    <cybox:Object id="MISP:Hostname-34cb1a7c-55ec-412a-8684-ba4a88d83a45">
                        <cybox:Properties xsi:type="HostnameObj:HostnameObjectType">
                            <HostnameObj:Hostname_Value condition="Equals">www.circl.lu</HostnameObj:Hostname_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
                    <cybox:Object id="MISP:Address-94a2b00f-bec3-4f8a-bea4-e4ccf0de776f">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_source="false" is_destination="true">
                            <AddressObj:Address_Value condition="Equals">149.13.33.14</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
                <cybox:Observable id="MISP:Observable-f2259650-bc33-4b64-a3a8-a324aa7ea6bb">
                    <cybox:Object id="MISP:Port-f2259650-bc33-4b64-a3a8-a324aa7ea6bb">
                        <cybox:Properties xsi:type="PortObj:PortObjectType">
                            <PortObj:Port_Value condition="Equals">443</PortObj:Port_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </cybox:Observable_Composition>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:39:53+00:00">
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

- user-account
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "description": "Object describing an user account",
        "uuid": "5d234f25-539c-4d12-bf93-2c46a964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "username",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "user-id",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "display-name",
                "value": "Code Monkey"
            },
            {
                "type": "text",
                "object_relation": "password",
                "value": "P4ssw0rd1234!"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "viktor-fan"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "donald-fan"
            },
            {
                "type": "text",
                "object_relation": "group-id",
                "value": "2004"
            },
            {
                "type": "text",
                "object_relation": "home_dir",
                "value": "/home/iglocska"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <stixCommon:RelatedObservableType>
        <stixCommon:Relationship>misc</stixCommon:Relationship>
        <stixCommon:Observable id="MISP:Observable-5d234f25-539c-4d12-bf93-2c46a964451a">
            <cybox:Object id="MISP:UserAccount-5d234f25-539c-4d12-bf93-2c46a964451a">
                <cybox:Properties xsi:type="UserAccountObj:UserAccountObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="user-id">iglocska</cyboxCommon:Property>
                        <cyboxCommon:Property name="group">viktor-fan</cyboxCommon:Property>
                        <cyboxCommon:Property name="group">donald-fan</cyboxCommon:Property>
                        <cyboxCommon:Property name="group-id">2004</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <AccountObj:Authentication>
                        <AccountObj:Authentication_Type>password</AccountObj:Authentication_Type>
                        <AccountObj:Authentication_Data>P4ssw0rd1234!</AccountObj:Authentication_Data>
                    </AccountObj:Authentication>
                    <UserAccountObj:Full_Name condition="Equals">Code Monkey</UserAccountObj:Full_Name>
                    <UserAccountObj:Home_Directory condition="Equals">/home/iglocska</UserAccountObj:Home_Directory>
                    <UserAccountObj:Username condition="Equals">iglocska</UserAccountObj:Username>
                </cybox:Properties>
            </cybox:Object>
        </stixCommon:Observable>
    </stixCommon:RelatedObservableType>
    ```

- user-account (with unix account type)
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "description": "Object describing an user account",
        "uuid": "5d234f25-539c-4d12-bf93-2c46a964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "username",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "user-id",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "display-name",
                "value": "Code Monkey"
            },
            {
                "type": "text",
                "object_relation": "password",
                "value": "P4ssw0rd1234!"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "viktor-fan"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "donald-fan"
            },
            {
                "type": "text",
                "object_relation": "group-id",
                "value": "2004"
            },
            {
                "type": "text",
                "object_relation": "home_dir",
                "value": "/home/iglocska"
            },
            {
                "type": "text",
                "object_relation": "account-type",
                "value": "unix"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <stixCommon:RelatedObservableType>
        <stixCommon:Relationship>misc</stixCommon:Relationship>
        <stixCommon:Observable id="MISP:Observable-5d234f25-539c-4d12-bf93-2c46a964451a">
            <cybox:Object id="MISP:UnixUserAccount-5d234f25-539c-4d12-bf93-2c46a964451a">
                <cybox:Properties xsi:type="UnixUserAccountObj:UnixUserAccountObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="user-id">iglocska</cyboxCommon:Property>
                        <cyboxCommon:Property name="group">viktor-fan</cyboxCommon:Property>
                        <cyboxCommon:Property name="group">donald-fan</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <AccountObj:Authentication>
                        <AccountObj:Authentication_Type>password</AccountObj:Authentication_Type>
                        <AccountObj:Authentication_Data>P4ssw0rd1234!</AccountObj:Authentication_Data>
                    </AccountObj:Authentication>
                    <UserAccountObj:Full_Name condition="Equals">Code Monkey</UserAccountObj:Full_Name>
                    <UserAccountObj:Home_Directory condition="Equals">/home/iglocska</UserAccountObj:Home_Directory>
                    <UserAccountObj:Username condition="Equals">iglocska</UserAccountObj:Username>
                    <UnixUserAccountObj:Group_ID condition="Equals">2004</UnixUserAccountObj:Group_ID>
                </cybox:Properties>
            </cybox:Object>
        </stixCommon:Observable>
    </stixCommon:RelatedObservableType>
    ```

- user-account (with windows account type)
  - MISP
    ```json
    {
        "name": "user-account",
        "meta-category": "misc",
        "description": "Object describing an user account",
        "uuid": "5d234f25-539c-4d12-bf93-2c46a964451a",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "username",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "user-id",
                "value": "iglocska"
            },
            {
                "type": "text",
                "object_relation": "display-name",
                "value": "Code Monkey"
            },
            {
                "type": "text",
                "object_relation": "password",
                "value": "P4ssw0rd1234!"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "viktor-fan"
            },
            {
                "type": "text",
                "object_relation": "group",
                "value": "donald-fan"
            },
            {
                "type": "text",
                "object_relation": "group-id",
                "value": "2004"
            },
            {
                "type": "text",
                "object_relation": "home_dir",
                "value": "/home/iglocska"
            },
            {
                "type": "text",
                "object_relation": "account-type",
                "value": "windows-local"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <stixCommon:RelatedObservableType>
        <stixCommon:Relationship>misc</stixCommon:Relationship>
        <stixCommon:Observable id="MISP:Observable-5d234f25-539c-4d12-bf93-2c46a964451a">
            <cybox:Object id="MISP:WindowsUserAccount-5d234f25-539c-4d12-bf93-2c46a964451a">
                <cybox:Properties xsi:type="WinUserAccountObj:WindowsUserAccountObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="group-id">2004</cyboxCommon:Property>
                        <cyboxCommon:Property name="account-type">windows-local</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <AccountObj:Authentication>
                        <AccountObj:Authentication_Type>password</AccountObj:Authentication_Type>
                        <AccountObj:Authentication_Data>P4ssw0rd1234!</AccountObj:Authentication_Data>
                    </AccountObj:Authentication>
                    <UserAccountObj:Full_Name condition="Equals">Code Monkey</UserAccountObj:Full_Name>
                    <UserAccountObj:Group_List>
                        <UserAccountObj:Group xsi:type='WinUserAccountObj:WindowsGroupType'>
                            <WinUserAccountObj:Name>viktor-fan</WinUserAccountObj:Name>
                        </UserAccountObj:Group>
                        <UserAccountObj:Group xsi:type='WinUserAccountObj:WindowsGroupType'>
                            <WinUserAccountObj:Name>donald-fan</WinUserAccountObj:Name>
                        </UserAccountObj:Group>
                    </UserAccountObj:Group_List>
                    <UserAccountObj:Home_Directory condition="Equals">/home/iglocska</UserAccountObj:Home_Directory>
                    <UserAccountObj:Username condition="Equals">iglocska</UserAccountObj:Username>
                    <WinUserAccountObj:Security_ID condition="Equals">iglocska</WinUserAccountObj:Security_ID>
                </cybox:Properties>
            </cybox:Object>
        </stixCommon:Observable>
    </stixCommon:RelatedObservableType>
    ```

- vulnerability
  - MISP
    ```json
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
                "value": "CVE-2017-11774"
            },
            {
                "type": "float",
                "object_relation": "cvss-score",
                "value": "6.8"
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
    ```
  - STIX
    ```xml
    <ttp:TTP id="MISP:TTP-5e579975-e9cc-46c6-a6ad-1611a964451a" timestamp="2021-01-12T15:57:42+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>vulnerability: vulnerability (MISP Object)</ttp:Title>
        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target id="MISP:ExploitTarget-5e579975-e9cc-46c6-a6ad-1611a964451a" timestamp="2021-01-12T15:57:42+00:00" xsi:type='et:ExploitTargetType'>
                    <et:Vulnerability>
                        <et:Description>Microsoft Outlook allow an attacker to execute arbitrary commands</et:Description>
                        <et:CVE_ID>CVE-2017-11774</et:CVE_ID>
                        <et:CVSS_Score>
    <et:Overall_Score>6.8</et:Overall_Score>
                        </et:CVSS_Score>
                        <et:Discovered_DateTime precision="second">2017-10-13T07:29:00</et:Discovered_DateTime>
                        <et:Published_DateTime precision="second">2017-10-13T07:29:00</et:Published_DateTime>
                        <et:References>
                            <stixCommon:Reference>http://www.securityfocus.com/bid/101098</stixCommon:Reference>
                            <stixCommon:Reference>https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11774</stixCommon:Reference>
                        </et:References>
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
        "name": "weakness",
        "meta-category": "vulnerability",
        "description": "Weakness object describing a common weakness",
        "uuid": "a1285743-3962-40e3-a824-0f21f10f3e19",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "text": "text",
                "object_relation": "id",
                "value": "CWE-119"
            },
            {
                "text": "text",
                "object_relation": "description",
                "value": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <ttp:TTP id="MISP:TTP-a1285743-3962-40e3-a824-0f21f10f3e19" timestamp="2021-01-12T15:58:15+00:00" xsi:type='ttp:TTPType'>
        <ttp:Title>vulnerability: weakness (MISP Object)</ttp:Title>
        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target id="MISP:ExploitTarget-a1285743-3962-40e3-a824-0f21f10f3e19" timestamp="2021-01-12T15:58:15+00:00" xsi:type='et:ExploitTargetType'>
                    <et:Weakness>
                        <et:Description>The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer</et:Description>
                        <et:CWE_ID>CWE-119</et:CWE_ID>
                    </et:Weakness>
                </stixCommon:Exploit_Target>
            </ttp:Exploit_Target>
        </ttp:Exploit_Targets>
    </ttp:TTP>
    ```

- whois
  - MISP
    ```json
    {
        "name": "whois",
        "meta-category": "network",
        "description": "Whois records information for a domain name or an IP address.",
        "uuid": "5b0d1b61-6c00-4387-a5fa-04370a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "whois-registrar",
                "object_relation": "registrar",
                "value": "Registrar"
            },
            {
                "type": "whois-registrant-email",
                "object_relation": "registrant-email",
                "value": "registrant@email.com"
            },
            {
                "type": "whois-registrant-org",
                "object_relation": "registrant-org",
                "value": "Registrant Org"
            },
            {
                "type": "whois-registrant-name",
                "object_relation": "registrant-name",
                "value": "Registrant Name"
            },
            {
                "type": "whois-registrant-phone",
                "object_relation": "registrant-phone",
                "value": "0123456789"
            },
            {
                "type": "datetime",
                "object_relation": "creation-date",
                "value": "2017-10-01T08:00:00"
            },
            {
                "type": "datetime",
                "object_relation": "modification-date",
                "value": "2020-10-25T16:22:00"
            },
            {
                "type": "datetime",
                "object_relation": "expiration-date",
                "value": "2021-01-01T00:00:00"
            },
            {
                "type": "domain",
                "object_relation": "domain",
                "value": "circl.lu"
            },
            {
                "type": "hostname",
                "object_relation": "nameserver",
                "value": "www.circl.lu"
            },
            {
                "type": "ip-src",
                "object_relation": "ip-address",
                "value": "1.2.3.4"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5b0d1b61-6c00-4387-a5fa-04370a00020f" timestamp="2021-01-12T15:59:11+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: whois (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>Whois records information for a domain name or an IP address.</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5b0d1b61-6c00-4387-a5fa-04370a00020f">
            <cybox:Object id="MISP:Whois-5b0d1b61-6c00-4387-a5fa-04370a00020f">
                <cybox:Properties xsi:type="WhoisObj:WhoisObjectType">
                    <WhoisObj:Domain_Name xsi:type="URIObj:URIObjectType">
                        <URIObj:Value>circl.lu</URIObj:Value>
                    </WhoisObj:Domain_Name>
                    <WhoisObj:IP_Address xsi:type="AddressObj:AddressObjectType">
                        <AddressObj:Address_Value>1.2.3.4</AddressObj:Address_Value>
                    </WhoisObj:IP_Address>
                    <WhoisObj:Nameservers>
                        <WhoisObj:Nameserver xsi:type="URIObj:URIObjectType">
                            <URIObj:Value>www.circl.lu</URIObj:Value>
                        </WhoisObj:Nameserver>
                    </WhoisObj:Nameservers>
                    <WhoisObj:Updated_Date condition="Equals" precision="day">2020-10-25T16:22:00</WhoisObj:Updated_Date>
                    <WhoisObj:Creation_Date condition="Equals" precision="day">2017-10-01T08:00:00</WhoisObj:Creation_Date>
                    <WhoisObj:Expiration_Date condition="Equals" precision="day">2021-01-01T00:00:00</WhoisObj:Expiration_Date>
                    <WhoisObj:Registrar_Info>
                        <WhoisObj:Name>Registrar</WhoisObj:Name>
                    </WhoisObj:Registrar_Info>
                    <WhoisObj:Registrants>
                        <WhoisObj:Registrant>
                            <WhoisObj:Name condition="Equals">Registrant Name</WhoisObj:Name>
                            <WhoisObj:Email_Address xsi:type="AddressObj:AddressObjectType" category="e-mail">
                                <AddressObj:Address_Value condition="Equals">registrant@email.com</AddressObj:Address_Value>
                            </WhoisObj:Email_Address>
                            <WhoisObj:Phone_Number condition="Equals">0123456789</WhoisObj:Phone_Number>
                            <WhoisObj:Organization condition="Equals">Registrant Org</WhoisObj:Organization>
                        </WhoisObj:Registrant>
                    </WhoisObj:Registrants>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:59:11+00:00">
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

- x509
  - MISP
    ```json
    {
        "name": "x509",
        "meta-category": "network",
        "description": "x509 object describing a X.509 certificate",
        "uuid": "5ac3444e-145c-4749-8467-02550a00020f",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "text",
                "object_relation": "issuer",
                "value": "Issuer Name"
            },
            {
                "type": "text",
                "object_relation": "pem",
                "value": "RawCertificateInPEMFormat"
            },
            {
                "type": "text",
                "object_relation": "pubkey-info-algorithm",
                "value": "PublicKeyAlgorithm"
            },
            {
                "type": "text",
                "object_relation": "pubkey-info-exponent",
                "value": "2"
            },
            {
                "type": "text",
                "object_relation": "pubkey-info-modulus",
                "value": "C5"
            },
            {
                "type": "text",
                "object_relation": "serial-number",
                "value": "1234567890"
            },
            {
                "type": "text",
                "object_relation": "signature-algorithm",
                "value": "SHA1_WITH_RSA_ENCRYPTION"
            },
            {
                "type": "text",
                "object_relation": "subject",
                "value": "CertificateSubject"
            },
            {
                "type": "datetime",
                "object_relation": "validity-not-before",
                "value": "2020-01-01T00:00:00"
            },
            {
                "type": "datetime",
                "object_relation": "validity-not-after",
                "value": "2021-01-01T00:00:00"
            },
            {
                "type": "text",
                "object_relation": "version",
                "value": "1"
            },
            {
                "type": "x509-fingerprint-md5",
                "object_relation": "x509-fingerprint-md5",
                "value": "b2a5abfeef9e36964281a31e17b57c97"
            },
            {
                "type": "x509-fingerprint-sha1",
                "object_relation": "x509-fingerprint-sha1",
                "value": "5898fc860300e228dcd54c0b1045b5fa0dcda502"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-5ac3444e-145c-4749-8467-02550a00020f" timestamp="2021-01-12T15:59:58+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>network: x509 (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>x509 object describing a X.509 certificate</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-5ac3444e-145c-4749-8467-02550a00020f">
            <cybox:Object id="MISP:X509Certificate-5ac3444e-145c-4749-8467-02550a00020f">
                <cybox:Properties xsi:type="X509CertificateObj:X509CertificateObjectType">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="x509-fingerprint-md5">b2a5abfeef9e36964281a31e17b57c97</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <X509CertificateObj:Certificate>
                        <X509CertificateObj:Version condition="Equals">1</X509CertificateObj:Version>
                        <X509CertificateObj:Serial_Number condition="Equals">1234567890</X509CertificateObj:Serial_Number>
                        <X509CertificateObj:Signature_Algorithm condition="Equals">SHA1_WITH_RSA_ENCRYPTION</X509CertificateObj:Signature_Algorithm>
                        <X509CertificateObj:Issuer condition="Equals">Issuer Name</X509CertificateObj:Issuer>
                        <X509CertificateObj:Validity>
                            <X509CertificateObj:Not_Before condition="Equals">2020-01-01T00:00:00</X509CertificateObj:Not_Before>
                            <X509CertificateObj:Not_After condition="Equals">2021-01-01T00:00:00</X509CertificateObj:Not_After>
                        </X509CertificateObj:Validity>
                        <X509CertificateObj:Subject condition="Equals">CertificateSubject</X509CertificateObj:Subject>
                        <X509CertificateObj:Subject_Public_Key>
                            <X509CertificateObj:Public_Key_Algorithm condition="Equals">PublicKeyAlgorithm</X509CertificateObj:Public_Key_Algorithm>
                            <X509CertificateObj:RSA_Public_Key>
                                <X509CertificateObj:Modulus condition="Equals">C5</X509CertificateObj:Modulus>
                                <X509CertificateObj:Exponent condition="Equals">2</X509CertificateObj:Exponent>
                            </X509CertificateObj:RSA_Public_Key>
                        </X509CertificateObj:Subject_Public_Key>
                    </X509CertificateObj:Certificate>
                    <X509CertificateObj:Raw_Certificate condition="Equals">RawCertificateInPEMFormat</X509CertificateObj:Raw_Certificate>
                    <X509CertificateObj:Certificate_Signature>
                        <X509CertificateObj:Signature_Algorithm condition="Equals">SHA1</X509CertificateObj:Signature_Algorithm>
                        <X509CertificateObj:Signature condition="Equals">5898fc860300e228dcd54c0b1045b5fa0dcda502</X509CertificateObj:Signature>
                    </X509CertificateObj:Certificate_Signature>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:59:58+00:00">
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


### Unmapped objects

As for attributes, the variety of available MISP object templates is larger than the STIX scope, which makes it impossible to map every MISP object to a specific STIX object.  
Again we do not skip those pieces of data and export them as `Custom` objects instead. Let us see some examples of custom objects exported from MISP objects:
- bank-account
  - MISP
    ```json
    {
        "name": "bank-account",
        "meta-category": "financial",
        "description": "An object describing bank account information based on account description from goAML 4.0",
        "uuid": "695e7924-2518-4054-9cea-f82853d37410",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "iban",
                "object_relation": "iban",
                "value": "LU1234567890ABCDEF1234567890"
            },
            {
                "type": "bic",
                "object_relation": "swift",
                "value": "CTBKLUPP"
            },
            {
                "type": "bank-account-nr",
                "object_relation": "account",
                "value": "1234567890"
            },
            {
                "type": "text",
                "object_relation": "institution-name",
                "value": "Central Bank"
            },
            {
                "type": "text",
                "object_relation": "account-name",
                "value": "John Smith's bank account"
            },
            {
                "type": "text",
                "object_relation": "beneficiary",
                "value": "John Smith"
            },
            {
                "type": "text",
                "object_relation": "currency-code",
                "value": "EUR"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-695e7924-2518-4054-9cea-f82853d37410" timestamp="2021-01-12T15:13:38+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>financial: bank-account (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>An object describing bank account information based on account description from goAML 4.0</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-695e7924-2518-4054-9cea-f82853d37410">
            <cybox:Object id="MISP:Custom-695e7924-2518-4054-9cea-f82853d37410">
                <cybox:Properties xsi:type="CustomObj:CustomObjectType" custom_name="bank-account">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="iban">LU1234567890ABCDEF1234567890</cyboxCommon:Property>
                        <cyboxCommon:Property name="swift">CTBKLUPP</cyboxCommon:Property>
                        <cyboxCommon:Property name="account">1234567890</cyboxCommon:Property>
                        <cyboxCommon:Property name="institution-name">Central Bank</cyboxCommon:Property>
                        <cyboxCommon:Property name="account-name">John Smith's bank account</cyboxCommon:Property>
                        <cyboxCommon:Property name="beneficiary">John Smith</cyboxCommon:Property>
                        <cyboxCommon:Property name="currency-code">EUR</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <CustomObj:Description>An object describing bank account information based on account description from goAML 4.0</CustomObj:Description>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:13:38+00:00">
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

- btc-wallet
  - MISP
    ```json
    {
        "name": "btc-wallet",
        "meta-category": "financial",
        "description": "An object to describe a Bitcoin wallet.",
        "uuid": "6f7509f1-f324-4acc-bf06-bbe726ab8fc7",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "btc",
                "object_relation": "wallet-address",
                "value": "1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE"
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
        ]
    }
    ```
  - STIX
    ```xml
    <indicator:Indicator id="MISP:Indicator-6f7509f1-f324-4acc-bf06-bbe726ab8fc7" timestamp="2021-01-12T15:13:38+00:00" xsi:type='indicator:IndicatorType'>
        <indicator:Title>financial: btc-wallet (MISP Object)</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
        <indicator:Description>An object to describe a Bitcoin wallet.</indicator:Description>
        <indicator:Valid_Time_Position/>
        <indicator:Observable id="MISP:Observable-6f7509f1-f324-4acc-bf06-bbe726ab8fc7">
            <cybox:Object id="MISP:Custom-6f7509f1-f324-4acc-bf06-bbe726ab8fc7">
                <cybox:Properties xsi:type="CustomObj:CustomObjectType" custom_name="btc-wallet">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="wallet-address">1E38kt7ryhbRXUzbam6iQ6sd93VHUUdjEE</cyboxCommon:Property>
                        <cyboxCommon:Property name="balance_BTC">2.25036953</cyboxCommon:Property>
                        <cyboxCommon:Property name="BTC_received">3.35036953</cyboxCommon:Property>
                        <cyboxCommon:Property name="BTC_sent">1.1</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <CustomObj:Description>An object to describe a Bitcoin wallet.</CustomObj:Description>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
        <indicator:Confidence timestamp="2021-01-12T15:13:38+00:00">
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

- person
  - MISP
    ```json
    {
        "name": "person",
        "meta-category": "misc",
        "description": "An object which describes a person or an identity.",
        "uuid": "868037d5-d804-4f1d-8016-f296361f9c68",
        "timestamp": "1603642920",
        "Attribute": [
            {
                "type": "first-name",
                "object_relation": "first-name",
                "value": "John"
            },
            {
                "type": "last-name",
                "object_relation": "last-name",
                "value": "Smith"
            },
            {
                "type": "nationality",
                "object_relation": "nationality",
                "value": "USA"
            },
            {
                "type": "passport-number",
                "object_relation": "passport-number",
                "value": "ABA9875413"
            },
            {
                "type": "phone-number",
                "object_relation": "phone-number",
                "value": "0123456789"
            }
        ]
    }
    ```
  - STIX
    ```xml
    <stixCommon:RelatedObservableType>
        <stixCommon:Relationship>misc</stixCommon:Relationship>
        <stixCommon:Observable id="MISP:Observable-868037d5-d804-4f1d-8016-f296361f9c68">
            <cybox:Object id="MISP:Custom-868037d5-d804-4f1d-8016-f296361f9c68">
                <cybox:Properties xsi:type="CustomObj:CustomObjectType" custom_name="person">
                    <cyboxCommon:Custom_Properties>
                        <cyboxCommon:Property name="first-name">John</cyboxCommon:Property>
                        <cyboxCommon:Property name="last-name">Smith</cyboxCommon:Property>
                        <cyboxCommon:Property name="nationality">USA</cyboxCommon:Property>
                        <cyboxCommon:Property name="passport-number">ABA9875413</cyboxCommon:Property>
                        <cyboxCommon:Property name="phone-number">0123456789</cyboxCommon:Property>
                    </cyboxCommon:Custom_Properties>
                    <CustomObj:Description>An object which describes a person or an identity.</CustomObj:Description>
                </cybox:Properties>
            </cybox:Object>
        </stixCommon:Observable>
    </stixCommon:RelatedObservableType>
    ```


## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events mapping](misp_events_to_stix1.md)
- [Attributes mapping](misp_attributes_to_stix1.md)
- [Galaxies mapping](misp_galaxies_to_stix1.md)

([Go back to the main documentation](README.md))
