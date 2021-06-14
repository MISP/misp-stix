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
| attachment | File & Artifact Objects |
| campaign-name | **Campaign** |
| domain | Domain Name Object |
| domain\|ip | Domain Name & IPv4/IPv6 Address Objects |
| email | Email Address Object |
| email-attachment | Email Message  & File Objects |
| email-body | Email Message Object |
| email-dst | Email Message & Email Address Objects |
| email-header | Email Message Object |
| email-reply-to | Email Message Object |
| email-src | Email Message & Email Address Objects |
| email-subject | Email Message Object |
| email-x-mailer | Email Message Object |
| filename | File Object |
| filename\|md5 | File Object |
| filename\|sha1 | File Object |
| filename\|sha224 | File Object |
| filename\|sha256 | File Object |
| filename\|sha384 | File Object |
| filename\|sha512 | File Object |
| filename\|sha512/224 | File Object |
| filename\|sha512/256 | File Object |
| filename\|sha3-224 | File Object |
| filename\|sha3-256 | File Object |
| filename\|sha3-384 | File Object |
| filename\|sha3-512 | File Object |
| filename\|ssdeep | File Object |
| filename\|tlsh | File Object |
| hostname | Domain Name Object |
| hostname\|port | Domain Name & Network Traffic Objects |
| http-method | Network Traffic Object (pattern) / Custom Object |
| ip-src | Network Traffic & IPv4/IPv6 Address Objects |
| ip-dst | Network Traffic & IPv4/IPv6 Address Objects |
| ip-src\|port | Network Traffic & IPv4/IPv6 Address Objects |
| ip-dst\|port | Network Traffic & IPv4/IPv6 Address Objects |
| link | URL Object |
| mac-address | Mac Address Object |
| malware-sample | File & Artifact Objects |
| md5 | File Object |
| mutex | Mutex Object |
| port | Network Traffic Object (pattern) / Custom Object |
| regkey | Windows Registry Key Object |
| regkey\|value | Windows Registry Key Object |
| sha1 | File Object |
| sha224 | File Object |
| sha256 | File Object |
| sha384 | File Object |
| sha512 | File Object |
| sha512/224 | File Object |
| sha512/256 | File Object |
| sha3-224 | File Object |
| sha3-256 | File Object |
| sha3-384 | File Object |
| sha3-512 | File Object |
| size-in-bytes | File Object (pattern) / Custom Object|
| ssdeep | File Object |
| tlsh | File Object |
| uri | URL Object |
| url | URL Object |
| user-agent | Network Traffic Object (pattern) / Custom Object|
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
| asn | Autonomous System Object |
| attack-pattern | **Attack Pattern** |
| course-of-action | **Course of Action** |
| credential | User Account Object |
| domain-ip | Domain Name & IPv4/IPv6 Address Objects |
| email | Email Message & Email Address Objects |
| facebook-account | User Account Object |
| file | File Object |
| file with references to pe & pe-section | File Object with Windows PE binary extension |
| ip-port | Network Traffic & IPv4/IPv6 Address Objects |
| mutex | Mutex Object |
| network-connection | Network Traffic, IPv4/IPv6 Address & Domain Name Objects |
| network-socket | Network Traffic with socket extension, IPv4/IPv6 Address & Domain Name Objects |
| pe | Windows PE binary extension within a File Object |
| pe-section | Sections fields in the Windows PE binary extension (always exported with the related pe object) |
| process | Process Object |
| registry-key | Windows Registry Key Object |
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
| android, backdoor, banker, malpedia, mitre-enterprise-attack-malware, mitre-malware, mitre-mobile-attack-malware, ransomware, stealer | **Malware** |
| microsoft-activity-group, threat-actor | **ThreatActor** |
| botnet, exploit-kit, mitre-enterprise-attack-tool, mitre-mobile-attack-tool, mitre-tool, rat, tds, tool | **Tool** |
| branded-vulneratbility | **Vulnerability** |

##### Detailed mapping

The detailed mapping for galaxies, with explanations and examples, is available [here](misp_galaxies_to_stix20.md)
