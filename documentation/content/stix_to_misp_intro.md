## STIX to MISP

When importing STIX 2.x content into MISP, the converter first determines the origin of the bundle to apply the appropriate parsing strategy:

- **Internal**: The bundle was originally produced by MISP (detected via the `misp:tool="MISP-STIX-Converter"` label on the `Report` or `Grouping` object). The import performs a faithful round-trip, reconstructing MISP attributes, objects, and galaxy clusters from MISP-specific custom types (`x-misp-attribute`, `x-misp-object`, `x-misp-galaxy-cluster`).

- **External**: The bundle was produced by a third-party tool. Standard STIX SDOs and SCOs are mapped to MISP attributes, objects, and galaxies using heuristics. SDOs that represent threat intelligence concepts (`AttackPattern`, `Malware`, `ThreatActor`, etc.) are imported as new MISP Galaxy Clusters.

Both use cases are documented for STIX 2.0 and STIX 2.1 in the sections below.

### Objects whose template name cannot be resolved

A MISP object names the template describing it, and an `x-misp-object` carries that name in
its `x_misp_name` property. A name that is not a plain template name — one holding a path
separator, a `..`, or any character a template directory does not use — is **not** resolved
as a template: the object is imported under the name `unknown-template`, with the name the
bundle sent kept in the object's `comment` so nothing is lost. A name that does resolve is
imported exactly as before, custom templates included. The same applies on export, to the
events and objects handed in as JSON: a stored name that cannot be a template is replaced
the same way rather than resolved again.