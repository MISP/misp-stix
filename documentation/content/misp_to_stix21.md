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

#### Attributes to STIX1 mapping

##### Summary

Most of the MISP attributes are converted into `Indicator` or `Observable` Objects.  
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

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix21.md)
