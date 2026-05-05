### STIX 2.1 to MISP

#### STIX 2.1 Bundles to MISP mapping

##### Summary

The import of STIX 2.1 content into MISP distinguishes between STIX bundles that were originally produced by MISP (internal) and those produced by third-party tools (external).

| STIX object | MISP datastructure |
| -- | -- |
| `Report` or `Grouping` | Event |
| `Indicator` | Attribute or Object (`to_ids` flag set) |
| `Observed Data` + SCOs | Attribute or Object (`to_ids` flag unset) |
| `AttackPattern`, `CourseOfAction`, `IntrusionSet`, `Malware`, `ThreatActor`, `Tool`, `Vulnerability` | Galaxy Cluster |

#### Attributes from STIX 2.1

##### Summary

The following table mentions the STIX 2.1 object types from which the MISP attributes are imported.

| MISP Attribute type | STIX Object type |
| -- | -- |
{_attributes_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](stix21_to_misp_attributes.md)

#### Objects from STIX 2.1

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
{_objects_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for MISP objects, with explanations and examples, is available [here](stix21_to_misp_objects.md)