## STIX to MISP

When importing STIX 2.x content into MISP, the converter first determines the origin of the bundle to apply the appropriate parsing strategy:

- **Internal**: The bundle was originally produced by MISP (detected via the `misp:tool="MISP-STIX-Converter"` label on the `Report` or `Grouping` object). The import performs a faithful round-trip, reconstructing MISP attributes, objects, and galaxy clusters from MISP-specific custom types (`x-misp-attribute`, `x-misp-object`, `x-misp-galaxy-cluster`).

- **External**: The bundle was produced by a third-party tool. Standard STIX SDOs and SCOs are mapped to MISP attributes, objects, and galaxies using heuristics. SDOs that represent threat intelligence concepts (`AttackPattern`, `Malware`, `ThreatActor`, etc.) are imported as new MISP Galaxy Clusters.

Both use cases are documented for STIX 2.0 and STIX 2.1 in the sections below.