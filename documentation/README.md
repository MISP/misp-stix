# MISP-STIX-Converter - Mapping documentation

This documentation describes how the conversion between MISP and STIX works in terms of mapping both formats together (as opposed to [the more generic description of the library itself](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/README.md), describing how to use it).  
Thus, it gives a detailed description of the inputs and outputs that are to expect depending on the type of data to convert.

## Summary

* [Introduction](#Introduction)
* [MISP to STIX](#MISP-to-STIX)
    * [MISP to STIX1](#MISP-to-STIX1)
        * [Events to STIX1](#Events-to-STIX1-mapping)
        * [Attributes to STIX1](#Attributes-to-STIX1-mapping)
        * [Objects to STIX1](#Objects-to-STIX1-mapping)
        * [Galaxies to STIX1](#Galaxies-to-STIX1-mapping)
    * [MISP to STIX 2.0](#MISP-to-STIX-20)
        * [Events to STIX 2.0](#Events-to-STIX-20-mapping)
        * [Attributes to STIX 2.0](#Attributes-to-STIX-20-mapping)
        * [Objects to STIX 2.0](#Objects-to-STIX-20-mapping)
        * [Galaxies to STIX 2.0](#Galaxies-to-STIX-20-mapping)
    * [MISP to STIX 2.1](#MISP-to-STIX-21)
        * [Events to STIX 2.1](#Events-to-STIX-21-mapping)
        * [Attributes to STIX 2.1](#Attributes-to-STIX-21-mapping)
        * [Objects to STIX 2.1](#Objects-to-STIX-21-mapping)
        * [Galaxies to STIX 2.1](#Galaxies-to-STIX-21-mapping)
* [Future improvements](#Future-Improvements)

## Introduction

MISP supports 2 majors features regarding STIX:
- The export of data collections from MISP to STIX
- The import of STIX content into a MISP Event

More specifically, MISP can generate **STIX1.1** and **STIX2.0** content from a given event using the UI (`Download as...` feature available in the event view), or any collection of event(s) using the built-in restSearch client.  
In order to do so, MISP gives data formatted in the standard misp format (used in every communication between connected MISP instances for example) to the corresponding export script (available within the [STIX export directory](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/misp_stix_converter/stix_export) of this repository) which returns STIX format.

It is also possible to import STIX data into MISP using again either the UI interface or the restSearch client (should support versions 1.1, 1.2, 2.0 and 2.1). In this case everything imported is put into a single MISP Event.  
In order to use that functionality, users can either pass the content of their STIX file to the restSearch client, or upload it using the `Import from...` feature available in the events list view. In both cases, the content of the file is then passed to the corresponding import script (available within the [STIX import directory](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/misp_stix_converter/stix_import) of this repository) which returns MISP format that is going to be saved as an Event in MISP.

Within this documentation we focus on the mapping between MISP and STIX formats.


## MISP to STIX


### MISP to STIX1

#### Events to STIX1 mapping

##### Summary

| MISP datastructure | STIX object|
| -- | -- |
| Event | `STIX Package` |
| Attribute | `Indicator` or `Observable` in most cases, `TTP`, `Journal entry` or `Custom Object` otherwise |
| Object | `Indicator` or `Observable` in most cases, `TTP`, `Threat Actor`, `Course of Action` or `Custom Object` otherwise |
| Galaxy | `TTP`, `Threat Actor`, or `Course of Action` |

##### Detailed mapping

The detailed mapping for events and its contained structures, with explanations and examples, is available [here](misp_events_to_stix1.md)

#### Attributes to STIX1 mapping

##### Summary

Most of the MISP attributes are converted into `Indicator` or `Observable` Objects.  
In the following table, all the object types preceded by any information about another object type are considered as being embedded in the list of `RelatedIndicators` or `RelatedObservables`.  
When they are exported neither as indicator nor as observable, the top level object type is mentioned.

| MISP Attribute type | STIX Object type - property name|
| -- | -- |
| AS | **ASObjectType** - Handle |
| attachment | **ArtifactObjectType** - Raw_Artifact |
| authentihash | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| campaign-name | *stix: Campaigns* -> **CampaignType** - Name -> Name|
| cdhash | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| comment | *incident: History* -> HistoryItem - Journal_Entry |
| domain | **DomainNameObjectType** - Value |
| domain\|ip | ObservableComposition -> **DomainNameObjectType** - Value \| **AddressObjectType** - Address_Value |
| email-attachment | **EmailMessageObjectType** - Attachments *referencing* **FileObjectType** - File_Name |
| email-body | **EmailMessageObjectType** - Raw_Body|
| email-dst | **EmailMessageObjectType** - To -> **AddressObjectType** - Address_Value |
| email-header | **EmailMessageObjectType** - Raw_Header |
| email-message-id | **EmailMessageObjectType** - Header -> Message_ID |
| email-mime-boundary | **EmailMessageObjectType** - Header -> Boundary |
| email-reply-to | **EmailMessageObjectType** - Reply_To -> **AddressObjectType** - Address_Value |
| email-src | **EmailMessageObjectType** - From -> **AddressObjectType** - Address_Value |
| email-subject | **EmailMessageObjectType** - Subject |
| email-x-mailer | **EmailMessageObjectType** - Header -> X_Mailer |
| filename | **FileObjectType** - File_Name |
| filename\|authentihash | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|impfuzzy | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|imphash | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|md5 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|pehash | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha1 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha224 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha256 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha384 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha512 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha512/224 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|sha512/256 | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|ssdeep | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|tlsh | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| filename\|vhash | **FileObjectType** - File_Name \& Hashes -> Hash - Simple_Hash_Value |
| hostname | **HostnameObjectType** - Hostname_Value |
| hostname\|port | **SocketAddressObjectType** - Hostname (**HostnameObjectType** - Hostname_Value) & Port (**PortObjectType** - Port_value)|
| http-method | **HTTPSessionObjectType** - HTTP_Method |
| impfuzzy | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| imphash | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| ip-dst | **AddressObjectType** - Address_Value |
| ip-dst\|port | **SocketAddressObjectType** - IP_Address (**AddressObjectType** - Address_Value) & Port (**PortObjectType** - Port_value) |
| ip-src | **AddressObjectType** - Address_Value |
| ip-src\|port | **SocketAddressObjectType** - IP_Address (**AddressObjectType** - Address_Value) & Port (**PortObjectType** - Port_value) |
| link | **URIObjectType** - Value |
| mac-address | **SystemObjectType** - Network_Interface_list -> Network_Interface - MAC |
| malware-sample | **ArtifactObjectType** - Raw_Artifact & Hashes -> Hash - Simple_Hash_Value |
| md5 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| mutex | **MutexObjectType** - Name |
| named pipe | **PipeObjectType** - Name |
| other | *incident: History* -> HistoryItem - Journal_Entry |
| pattern-in-file | **FileObjectType** - Byte_Runs -> Byte_Run - Byte_Run_Data |
| pehash | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| port | **PortObjectType** - Port_Value |
| regkey | **WindowsRegistryKeyObjectType** - Key |
| regkey\|value | **WindowsRegistryKeyObjectType** - Key & Values -> Value - Data |
| sha1 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha224 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha256 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha384 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha512 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha512/224 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| sha512/256 | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| size-in-bytes | **FileObjectType** - Size_In_Bytes |
| snort | *indicator: Test_Mechanisms* -> **SnortTestMechanismType** - Rule |
| ssdeep | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| target-email | *incident: Victim* -> **CIQIdentity3.0InstanceType** - ElectronicAddressIdentifiers - ElectronicAddressIdentifier |
| target-external | *incident: Victim* -> **CIQIdentity3.0InstanceType** - PartyName - NameLine |
| target-location | *incident: Victim* -> **CIQIdentity3.0InstanceType** - Addresses -> Address - FreeTextAddress - AddressLine |
| target-machine | *incident: Affected_Assets* -> Affected_Asset - Description |
| target-org | *incident: Victim* -> **CIQIdentity3.0InstanceType** - PartyName -> OrganisationName - NameElement |
| target-user | *incident: Victim* -> **CIQIdentity3.0InstanceType** - PartyName -> PersonName - NameElement |
| text | *incident: History* -> HistoryItem - Journal_Entry |
| tlsh | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| uri | **URIObjectType** - Value |
| url | **URIObjectType** - Value |
| user-agent | **HTTPSessionObjectType** - HTTP_Request_Response -> HTTP_Client_Request -> HTTP_Request_Header -> Parsed_Header - User_Agent |
| vhash | **FileObjectType** - Hashes -> Hash - Simple_Hash_Value |
| vulnerability | *stix: TTPs* -> **TTPType** - Exploit_Targets -> **ExploitTargetType** -> Vulnerability - CVE_ID |
| weakness | *stix: TTPs* -> **TTPType** - Exploit_targets -> **ExploitTargetType** -> Weakness - CWE_ID |
| whois-registrant-email | **WhoisObjectType** - Registrants -> Registrant - Email_Address -> **AddressObjectType** - Address_Value |
| whois-registrant-name | **WhoisObjectType** - Registrants -> Registrant - Name |
| whois-registrant-org | **WhoisObjectType** - Registrants -> Registrant - Organization |
| whois-registrant-phone | **WhoisObjectType** - Registrants -> Registrant - Phone_Number |
| whois-registrar | **WhoisObjectType** - Registrar_Info -> Name |
| windows-service-displayname | **WindowsServiceObjectType** - Display_Name |
| windows-service-name | **WindowsServiceObjectType** - Service_Name |
| x509-fingerprint-md5 | **X509CertificateObjectType** - Certificate_Signature - Signature |
| x509-fingerprint-sha1 | **X509CertificateObjectType** - Certificate_Signature - Signature |
| x509-fingerprint-sha256 | **X509CertificateObjectType** - Certificate_Signature - Signature |
| yara | *indicator: Test_Mechanisms* -> **YaraTestMechanismType** - Rule |

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix1.md)

#### Objects to STIX1 mapping

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
| asn | **ASObjectType** |
| attack-pattern | **TTPType** - Behavior - Attack_Patterns |
| course-of-action | **CourseOfActionType** |
| credential | **UserAccountObjectType** |
| domain-ip | ObservableComposition -> **DomainNameObjectType** \| **AddressObjectType** |
| email | **EmailMessageObjectType** |
| file | **FileObjectType** |
| file with references to pe \& pe-section objects | **WindowsExecutableFileObjectType** |
| ip-port | ObservableComposition -> **AddressObjectType** \| **PortObjectType** |
| mutex | **MutexObjectType** |
| network-connection | **NetworkConnectionObjectType** |
| network-socket | **NetworkSocketObjectType** |
| process | **ProcessObjectType** |
| registry-key | **WindowsRegistryKeyObjectType** |
| url | **URIObjectType** |
| user-account | **UserAccountObjectType** |
| user-account with `unix` as `account-type` attribute value | **UnixUserAccountObjectType** |
| user-account with `windows-local` as `account-type` attribute value | **WindowsUserAccountObjectType** |
| vulnerability | **TTPType** - Exploit_Target - Vulnerability |
| weakness | **TTPType** - Exploit_Target - Weakness |
| whois | **WhoisObjectType** |
| x509 | **X509CertificateObjectType** |

##### Detailed mapping

The detailed mapping for objects, with explanations and examples, is available [here](misp_objects_to_stix1.md)

#### Galaxies to STIX1 mapping

##### Summary

| MISP Galaxy Clusters name | STIX Object type |
| -- | -- |
| android, backdoor, banker, malpedia, mitre-enterprise-attack-malware, mitre-malware, mitre-mobile-attack-malware, ransomware, stealer | *stix: TTPs* -> **TTPType** - Behavior -> Malware - Malware_Instance |
| botnet, exploit-kit, mitre-enterprise-attack-tool, mitre-mobile-attack-tool, mitre-tool, rat, tds, tool | *stix: TTPs* -> **TTPType** - Resources -> Tools -> Tool |
| branded-vulneratbility | *stix: TTPs* -> **TTPType** - Exploit_targets -> **ExploitTargetType** - Vulnerability |
| microsoft-activity-group, threat-actor | *stix: Threat_Actors* -> **ThreatActorType** |
| mitre-attack-pattern, mitre-enterprise-attack-attack-pattern, mitre-mobile-attack-attack-pattern, mitre-pre-attack-attack-pattern | *stix: TTPs* -> **TTPType** - Behavior -> Attack_Patterns -> Attack_Pattern |
| mitre-course-of-action, mitre-enterprise-attack-course-of-action, mitre-mobile-attack-course-of-action | *stix: Courses_Of_action* -> **CourseOfActionType** |

##### Detailed mapping

The detailed mapping for galaxies, with explanations and examples, is available [here](misp_galaxies_to_stix1.md)


### MISP to STIX 2.0

#### Events to STIX 2.0 mapping

##### Summary

| MISP datastructure | STIX object|
| -- | -- |
| Event | `Report` |
| Attribute | `Indicator` or `Observable` in most cases, `Vulnerability`, `Campaign` or `Custom Object` otherwise |
| Object | `Indicator` or `Observable` in most cases, `Vulnerability`, `Threat Actor`, `Course of Action` or `Custom Object` otherwise |
| Galaxy | `Vulnerability`, `Threat Actor`, or `Course of Action` |

##### Detailed mapping

The detailed mapping for events and its contained structures, with explanations and examples, is available [here](misp_events_to_stix20.md)

#### Attributes to STIX 2.0 mapping

##### Summary

Most of the MISP attributes are converted into `Indicator` or `Observed Data` Objects.  
The following table mentions then the patterning expression or `Observable Object` type the attributes are exported into, respectively within the Indicator or Observed Data object.  
When another object type is mentioned in bold, it means the corresponding attribute is neither exported as Indicator nor as Observed Data.

| MISP Attribute type | STIX Object type / Observable Object type |
| -- | -- |
| AS | Autonomous System Object |
| attachment | Artifact & File Objects |
| authentihash | File Object |
| campaign-name | **Campaign** |
| domain | Domain Name Object |
| domain\|ip | Domain Name & IPv4/IPv6 Address Objects |
| email | Email Address Object |
| email-attachment | Email Message & File Objects |
| email-body | Email Message Object |
| email-dst | Email Address & Email Message Objects |
| email-header | Email Message Object |
| email-reply-to | Email Message Object |
| email-src | Email Address & Email Message Objects |
| email-subject | Email Message Object |
| email-x-mailer | Email Message Object |
| filename | File Object |
| filename\|authentihash | File Object |
| filename\|imphash | File Object |
| filename\|md5 | File Object |
| filename\|pehash | File Object |
| filename\|sha1 | File Object |
| filename\|sha224 | File Object |
| filename\|sha256 | File Object |
| filename\|sha3-224 | File Object |
| filename\|sha3-256 | File Object |
| filename\|sha3-384 | File Object |
| filename\|sha3-512 | File Object |
| filename\|sha384 | File Object |
| filename\|sha512 | File Object |
| filename\|sha512/224 | File Object |
| filename\|sha512/256 | File Object |
| filename\|ssdeep | File Object |
| filename\|tlsh | File Object |
| filename\|vhash | File Object |
| github-username | User Account Object (pattern) / Custom Object |
| hostname | Domain Name Object |
| hostname\|port | Domain Name & Network Traffic Objects |
| http-method | Network Traffic Object (pattern) / Custom Object |
| imphash | File Object |
| ip-dst | IPv4/IPv6 Address & Network Traffic Objects |
| ip-dst\|port | IPv4/IPv6 Address & Network Traffic Objects |
| ip-src | IPv4/IPv6 Address & Network Traffic Objects |
| ip-src\|port | IPv4/IPv6 Address & Network Traffic Objects |
| link | URL Object |
| mac-address | Mac Address Object |
| malware-sample | Artifact & File Objects |
| md5 | File Object |
| mutex | Mutex Object |
| pehash | File Object |
| port | Network Traffic Object (pattern) / Custom Object |
| regkey | Windows Registry Key Object |
| regkey\|value | Windows Registry Key Object |
| sha1 | File Object |
| sha224 | File Object |
| sha256 | File Object |
| sha3-224 | File Object |
| sha3-256 | File Object |
| sha3-384 | File Object |
| sha3-512 | File Object |
| sha384 | File Object |
| sha512 | File Object |
| sha512/224 | File Object |
| sha512/256 | File Object |
| size-in-bytes | File Object (pattern) / Custom Object |
| ssdeep | File Object |
| telfhash | File Object |
| tlsh | File Object |
| uri | URL Object |
| url | URL Object |
| user-agent | Network Traffic Object (pattern) / Custom Object |
| vhash | File Object |
| vulnerability | **Vulnerability** |
| x509-fingerprint-md5 | X509 Certificate Object |
| x509-fingerprint-sha1 | X509 Certificate Object |
| x509-fingerprint-sha256 | X509 Certificate Object |

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix20.md)

#### Objects to STIX 2.0 mapping

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
| Script object where state is "Malicious" | **Malware** |
| Script object where state is not "Malicious" | **Tool** |
| android-app | Software Object |
| asn | Autonomous System Object |
| attack-pattern | **Attack Pattern** |
| course-of-action | **Course of Action** |
| cpe-asset | Software Object |
| credential | User Account Object |
| domain-ip | Domain Name & IPv4/IPv6 Address Objects |
| email | Email Address & Email Message & File Objects |
| email with display names | Email Address & Email Message Objects |
| employee | **Identity** |
| facebook-account | User Account Object |
| file | File Object (potential references to Artifact & Directory Objects) |
| file with references to pe & pe-section(s) | File Object with a Windows PE binary extension |
| github-user | User Account Object |
| gitlab-user | User Account Object |
| http-request | Domain Name & IPv4/IPv6 Address & Network Traffic Objects |
| identity | **Identity** |
| image | Artifact & File Objects |
| ip-port | IPv4/IPv6 Address & Network Traffic Objects |
| legal-entity | **Identity** |
| lnk | Artifact & Directory & File Objects |
| mutex | Mutex Object |
| netflow | Autonomous System & IPv4/IPv6 Address & Network Traffic Objects |
| network-connection | Network Traffic, IPv4/IPv6 Address & Domain Name Objects |
| network-socket | Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects |
| news-agency | **Identity** |
| organization | **Identity** |
| parler-account | User Account Object |
| pe | Windows PE binary extension within a File Object |
| pe & pe-sections | Windows PE binary extension within a File Object |
| pe-section | Sections fields in the Windows PE binary extension (always exported with the related pe object) |
| person | **Identity** |
| process | Process Objects (potential reference to File Objects) |
| reddit-account | User Account Object |
| registry-key | Windows Registry Key Object |
| telegram-account | User Account Object |
| twitter-account | User Account Object |
| url | URL Object |
| user-account | User Account Object |
| vulnerability | **Vulnerability** |
| x509 | X509 Certificate Object |

##### Detailed mapping

The detailed mapping for MISP objects, with explanations and examples, is available [here](misp_objects_to_stix20.md)

#### Galaxies to STIX 2.0 mapping

##### Summary

| MISP Galaxy Clusters name | STIX Object type |
| -- | -- |
| mitre-attack-pattern, mitre-enterprise-attack-attack-pattern, mitre-mobile-attack-attack-pattern, mitre-pre-attack-attack-pattern | **AttackPattern** |
| mitre-course-of-action, mitre-enterprise-attack-course-of-action, mitre-mobile-attack-course-of-action | **CourseOfAction** |
| mitre-enterprise-attack-intrusion-set, mitre-intrusion-set, mitre-mobile-attack-intrusion-set, mitre-pre-attack-intrusion-set | **IntrusionSet** |
| android, backdoor, banker, malpedia, mitre-enterprise-attack-malware, mitre-malware, mitre-mobile-attack-malware, ransomware, stealer | **Malware** |
| microsoft-activity-group, threat-actor | **ThreatActor** |
| botnet, exploit-kit, mitre-enterprise-attack-tool, mitre-mobile-attack-tool, mitre-tool, rat, tds, tool | **Tool** |
| branded-vulneratbility | **Vulnerability** |

##### Detailed mapping

The detailed mapping for galaxies, with explanations and examples, is available [here](misp_galaxies_to_stix20.md)


### MISP to STIX 2.1

#### Events to STIX 2.1 mapping

##### Summary

| MISP datastructure | STIX object|
| -- | -- |
| Event | `Report` or `Grouping` |
| Attribute | `Indicator` or `Observable` in most cases, `Vulnerability`, `Campaign` or `Custom Object` otherwise |
| Object | `Indicator` or `Observable` in most cases, `Vulnerability`, `Threat Actor`, `Course of Action` or `Custom Object` otherwise |
| Galaxy | `Vulnerability`, `Threat Actor`, or `Course of Action` |

##### Detailed mapping

The detailed mapping for events and its contained structures, with explanations and examples, is available [here](misp_events_to_stix21.md)

#### Attributes to STIX 2.1 mapping

##### Summary

Most of the MISP attributes are converted into `Indicator` or `Observable` Objects.  
The following table mentions then the patterning expression or `Observable Object` type the attributes are exported into, respectively within the Indicator or Observed Data object.  
When another object type is mentioned in bold, it means the corresponding attribute is neither exported as Indicator nor as Observed Data.

| MISP Attribute type | STIX Object type / Observable Object type |
| -- | -- |
| AS | Autonomous System Object |
| attachment | Artifact & File Objects |
| authentihash | File Object |
| campaign-name | **Campaign** |
| domain | Domain Name Object |
| domain\|ip | Domain Name & IPv4/IPv6 Address Objects |
| email | Email Address Object |
| email-attachment | Email Message & File Objects |
| email-body | Email Message Object |
| email-dst | Email Address & Email Message Objects |
| email-header | Email Message Object |
| email-message-id | Email Message Object |
| email-reply-to | Email Message Object |
| email-src | Email Address & Email Message Objects |
| email-subject | Email Message Object |
| email-x-mailer | Email Message Object |
| filename | File Object |
| filename\|authentihash | File Object |
| filename\|imphash | File Object |
| filename\|md5 | File Object |
| filename\|pehash | File Object |
| filename\|sha1 | File Object |
| filename\|sha224 | File Object |
| filename\|sha256 | File Object |
| filename\|sha3-224 | File Object |
| filename\|sha3-256 | File Object |
| filename\|sha3-384 | File Object |
| filename\|sha3-512 | File Object |
| filename\|sha384 | File Object |
| filename\|sha512 | File Object |
| filename\|sha512/224 | File Object |
| filename\|sha512/256 | File Object |
| filename\|ssdeep | File Object |
| filename\|tlsh | File Object |
| filename\|vhash | File Object |
| github-username | User Account Object |
| hostname | Domain Name Object |
| hostname\|port | Domain Name & Network Traffic Objects |
| http-method | Network Traffic Object (pattern) / Custom Object |
| imphash | File Object |
| ip-dst | IPv4/IPv6 Address & Network Traffic Objects |
| ip-dst\|port | IPv4/IPv6 Address & Network Traffic Objects |
| ip-src | IPv4/IPv6 Address & Network Traffic Objects |
| ip-src\|port | IPv4/IPv6 Address & Network Traffic Objects |
| link | URL Object |
| mac-address | Mac Address Object |
| malware-sample | Artifact & File Objects |
| md5 | File Object |
| mutex | Mutex Object |
| pehash | File Object |
| port | Network Traffic Object (pattern) / Custom Object |
| regkey | Windows Registry Key Object |
| regkey\|value | Windows Registry Key Object |
| sha1 | File Object |
| sha224 | File Object |
| sha256 | File Object |
| sha3-224 | File Object |
| sha3-256 | File Object |
| sha3-384 | File Object |
| sha3-512 | File Object |
| sha384 | File Object |
| sha512 | File Object |
| sha512/224 | File Object |
| sha512/256 | File Object |
| sigma | **Indicator** |
| size-in-bytes | File Object (pattern) / Custom Object |
| snort | **Indicator** |
| ssdeep | File Object |
| telfhash | File Object |
| tlsh | File Object |
| uri | URL Object |
| url | URL Object |
| user-agent | Network Traffic Object (pattern) / Custom Object |
| vhash | File Object |
| vulnerability | **Vulnerability** |
| x509-fingerprint-md5 | X509 Certificate Object |
| x509-fingerprint-sha1 | X509 Certificate Object |
| x509-fingerprint-sha256 | X509 Certificate Object |
| yara | **Indicator** |

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix21.md)

#### Objects to STIX 2.1 mapping

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
| Script object where state is "Malicious" | **Malware** |
| Script object where state is not "Malicious" | **Tool** |
| android-app | Software Object |
| annotation | **Note** |
| asn | Autonomous System Object |
| attack-pattern | **Attack Pattern** |
| course-of-action | **Course of Action** |
| cpe-asset | Software Object |
| credential | User Account Object |
| domain-ip | Domain Name & IPv4/IPv6 Address Objects |
| domain-ip with the perfect domain & ip matching | A tuple of IPv4/IPv6 Address & Network Objects for each associated domain & ip |
| email | Email Address & Email Message & File Objects |
| email with display names | Email Address & Email Message & Observed Data Objects |
| employee | **Identity** |
| facebook-account | User Account Object |
| file | File Object (potential references to Artifact & Directory Objects) |
| file with references to pe & pe-section | File Object with a windows pebinary extension |
| file with references to pe & pe-section(s) | File Object with a Windows PE binary extension |
| geolocation | **Location** |
| github-user | User Account Object |
| gitlab-user | User Account Object |
| http-request | Domain Name & IPv4/IPv6 Address & Network Traffic Objects |
| identity | **Identity** |
| image | Artifact & File Objects |
| ip-port | IPv4/IPv6 Address & Network Traffic Objects |
| legal-entity | **Identity** |
| lnk | Artifact & Directory & File Objects |
| mutex | Mutex Object |
| netflow | Autonomous System & IPv4/IPv6 Address & Network Traffic Objects |
| network-connection | Network Traffic, IPv4/IPv6 Address & Domain Name Objects |
| network-socket | Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects |
| news-agency | **Identity** |
| organization | **Identity** |
| parler-account | User Account Object |
| pe | Windows PE binary extension within a File Object |
| pe & pe-sections | Windows PE binary extension within a File Object |
| pe-section | Sections fields in the Windows PE binary extension (always exported with the related pe object) |
| person | **Identity** |
| process | Process Objects (potential reference to File Objects) |
| reddit-account | User Account Object |
| registry-key | Windows Registry Key Object |
| sigma | **Indicator** |
| suricata | **Indicator** |
| telegram-account | User Account Object |
| twitter-account | User Account Object |
| url | URL Object |
| user-account | User Account Object |
| vulnerability | **Vulnerability** |
| x509 | X509 Certificate Object |
| yara | **Indicator** |

##### Detailed mapping

The detailed mapping for MISP objects, with explanations and examples, is available [here](misp_objects_to_stix21.md)

#### Galaxies to STIX 2.1 mapping

##### Summary

| MISP Galaxy Clusters name | STIX Object type |
| -- | -- |
| mitre-attack-pattern, mitre-enterprise-attack-attack-pattern, mitre-mobile-attack-attack-pattern, mitre-pre-attack-attack-pattern | **AttackPattern** |
| mitre-course-of-action, mitre-enterprise-attack-course-of-action, mitre-mobile-attack-course-of-action | **CourseOfAction** |
| mitre-enterprise-attack-intrusion-set, mitre-intrusion-set, mitre-mobile-attack-intrusion-set, mitre-pre-attack-intrusion-set | **IntrusionSet** |
| android, backdoor, banker, malpedia, mitre-enterprise-attack-malware, mitre-malware, mitre-mobile-attack-malware, ransomware, stealer | **Malware** |
| microsoft-activity-group, threat-actor | **ThreatActor** |
| botnet, exploit-kit, mitre-enterprise-attack-tool, mitre-mobile-attack-tool, mitre-tool, rat, tds, tool | **Tool** |
| branded-vulneratbility | **Vulnerability** |

##### Detailed mapping

The detailed mapping for galaxies, with explanations and examples, is available [here](misp_galaxies_to_stix21.md)
