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

#### Galaxies from STIX 2.1

##### Summary

| STIX Object type | MISP Galaxy |
| -- | -- |
{_galaxies_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for MISP galaxies from STIX 2.1 bundles, with explanations and examples, is available [here](stix21_to_misp_galaxies.md)

#### Attributes from External STIX 2.1

##### Summary

| MISP Attribute type | STIX Object type |
| -- | -- |
{_external_attributes_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for attributes from external STIX 2.1 bundles, with explanations and examples, is available [here](external_stix21_to_misp_attributes.md)

#### Objects from External STIX 2.1

##### Summary

| MISP Object name | STIX Object type |
| -- | -- |
{_external_objects_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for MISP objects from external STIX 2.1 bundles, with explanations and examples, is available [here](external_stix21_to_misp_objects.md)

#### Galaxies from External STIX 2.1

SDOs in STIX 2.1 bundles produced by third-party tools are imported as new MISP Galaxy Clusters with galaxy type `stix-2.1-{{object-type}}`.

##### Summary

| STIX Object type | MISP Galaxy |
| -- | -- |
{_external_galaxies_from_stix21_summary_}

##### Detailed mapping

The detailed mapping for MISP galaxies from external STIX 2.1 bundles, with explanations and examples, is available [here](external_stix21_to_misp_galaxies.md)