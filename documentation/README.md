# MISP-STIX-Converter - Mapping documentation

This documentation describes how the conversion between MISP and STIX works in terms of mapping both formats together (as opposed to [the more generic description of the library itself](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/README.md), describing how to use it).  
Thus, it gives a detailed description of the inputs and outputs that are to expect depending on the type of data to convert.

## Summary

* [Introduction](#Introduction)
* [MISP to STIX](#MISP-to-STIX)
    * [MISP to STIX1](#MISP-to-STIX1)

## Introduction


## MISP to STIX




<table style="white-space:nowrap;width:100%;">
<tr>
<td> Attribute type </td> <td class="block" style="width:45%"> MISP </td> <td class="block" style="width:45%"> STIX </td>
</tr>
<tr>
<td> AS </td>
<td>

```json
{
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "AS",
    "category": "Network activity",
    "value": "AS174",
    "to_ids": false
}
```

</td>
<td>

```xml
<cybox:ObservableType id="MISP:Observable-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
    <cybox:Object id="MISP:AutonomousSystem-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f">
        <cybox:Properties xsi:type="ASObj:ASObjectType">
            <ASObj:Handle condition="Equals">AS174</ASObj:Handle>
        </cybox:Properties>
    </cybox:Object>
</cybox:ObservableType>
```

</td>
</tr>
<tr>
<td> attachment </td>
<td>

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

</td>
<td>

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

</td>
</tr>
<tr>
<td> domain </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:00:14+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:00:14+00:00">
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

</td>
</tr>
<tr>
<td> domain|ip </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:07:20+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:07:20+00:00">
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

</td>
</tr>
<tr>
<td> email-attachment </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:07:20+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:07:20+00:00">
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

</td>
</tr>
<tr>
<td> email-dst </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> email-src </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> email-reply-to </td>
<td>

```json
{
    "uuid": "94a2b00f-bec3-4f8a-bea4-e4ccf0de776f",
    "type": "email-reply-to",
    "category": "Payload delivery",
    "value": "reply-to@email.test",
    "to_ids": false
}
```

</td>
<td>

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

</td>
</tr>
<tr>
<td> email-subject </td>
<td>

```json
{
    "uuid": "34cb1a7c-55ec-412a-8684-ba4a88d83a45",
    "type": "email-subject",
    "category": "Payload delivery",
    "value": "Test Subject",
    "to_ids": false
}
```

</td>
<td>

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

</td>
</tr>
<tr>
<td> filename </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> filename|md5 </td>
<td>

```json
{
    "uuid": "91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f",
    "type": "filename|md5",
    "category": "Payload delivery",
    "value": "test_file_name|b2a5abfeef9e36964281a31e17b57c97",
    "timestamp": "1603642920",
    "comment": "Filename|md5 test attribute",
    "to_ids": true
}
```

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
    <indicator:Title>Payload delivery: test_file_name|b2a5abfeef9e36964281a31e17b57c97 (MISP Attribute)</indicator:Title>
    <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
    <indicator:Description>Filename|md5 test attribute</indicator:Description>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> filename|tlsh </td>
<td>

```json
{
    "uuid": "518b4bcb-a86b-4783-9457-391d548b605b",
    "type": "filename|tlsh",
    "category": "Payload delivery",
    "value": "test_file_name|1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1",
    "timestamp": "1603642920",
    "comment": "Filename|tlsh test attribute",
    "to_ids": true
}
```

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
    <indicator:Title>Payload delivery: test_file_name|1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1 (MISP Attribute)</indicator:Title>
    <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
    <indicator:Description>Filename|tlsh test attribute</indicator:Description>
    <indicator:Valid_Time_Position/>
    <indicator:Observable id="MISP:Observable-518b4bcb-a86b-4783-9457-391d548b605b">
        <cybox:Object id="MISP:File-518b4bcb-a86b-4783-9457-391d548b605b">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name condition="Equals">test_file_name</FileObj:File_Name>
                <FileObj:Hashes>
                    <cyboxCommon:Hash>
                        <cyboxCommon:Type condition="Equals">Other</cyboxCommon:Type>
                        <cyboxCommon:Simple_Hash_Value condition="Equals">1b14cf6a6e934907e8133934b2cec5e01fbc5dafabc3156fdb51bd2c48d410986869f1</cyboxCommon:Simple_Hash_Value>
                    </cyboxCommon:Hash>
                </FileObj:Hashes>
            </cybox:Properties>
        </cybox:Object>
    </indicator:Observable>
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> md5 </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
<tr>
<td> tlsh </td>
<td>

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

</td>
<td>

```xml
<indicator:Indicator id="MISP:Indicator-518b4bcb-a86b-4783-9457-391d548b605b" timestamp="2020-11-06T17:10:45+00:00" xsi:type='indicator:IndicatorType'>
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
    <indicator:Confidence timestamp="2020-11-06T17:10:45+00:00">
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

</td>
</tr>
</table>