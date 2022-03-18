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
{_attributes_to_stix20_summary_}

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix20.md)

#### Objects to STIX 2.0 mapping

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
{_objects_to_stix20_summary_}

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
